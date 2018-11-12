#!/usr/bin/python
# Ccrypt
# Some implementations of classical cipher primitives and
# cryptanalysis functions.
#
# Author: xdrr

import sys
import binascii
import struct
import itertools
import string
import magic
from binascii import hexlify, unhexlify
from collections import Counter
from nltk import ngrams
import base64
import fractions

## Assumes GNU Linux
with open('/usr/share/dict/american-english') as f:
    WORDS = f.read()
WORDS = list(WORDS.split('\n'))
BAD_WORDS = [ 'q', 'X' ]

## XOR repeating cipher
def xor_repeat(c,k):
    return ''.join([chr(ord(c[i])^ord(k[i%len(k)])) for i in range(len(c))])

## XOR monoalphabetic cipher
def xor_c(c,k):
    return ''.join([chr(ord(c[i])^ord(k)) for i in range(len(c))])

## OR monoalphabetic cipher
def or_c(c,k):
    return ''.join([chr(ord(c[i]) | ord(k)) for i in range(len(c))])

## AND monoalphabetic cipher
def and_c(c,k):
    return ''.join([chr(ord(c[i]) & ord(k)) for i in range(len(c))])

## Mono-byte transposition cipher
def byte_shift(c,n):
    return ''.join([chr((ord(c[i])+n) % 255) for i in range(len(c))])

## Polyalphabetic transposition cipher
def poly_shift(c, k):
    return ''.join([chr((ord(c[i])+ord(k[i%len(k)])) % 255) for i in range(len(c))])

## Decrypts above
def poly_unshift(c, k):
    return ''.join([chr((ord(c[i])-ord(k[i%len(k)])) % 255) for i in range(len(c))])

## Search for polyalphabetic transposition cipher keys
## filt is the user provided fitness test with signature func(x)
## where x is candidate key.
def find_poly_keys(c, n, filt):
    keys = itertools.product(map(lambda x: chr(x), range(255)), repeat=n)
    possible_keys = list()
    for key in keys:
        key = ''.join(key)
        p = poly_unshift(c, key)
        if filt(p):
            possible_keys.append(key)
    return possible_keys

## Brute force polyalphabetic transpositional ciphertext
## filt1 and filt2 are user-provided fitness tests
## that filter the possible keys for the first ciphertext
## period n, and filter the decrypted ciphertext, respectively.
def brute_poly_unshift(c, n, filt1, filt2):
    if filt1 == None or filt2 == None:
        raise Exception("A filter must be specified")
    ## Find keys that meet filter criteria for first
    ## period.
    possible_keys = find_poly_keys(c[:n], n, filt1)
    solves = list()
    for key in possible_keys:
        key = ''.join(key)
        p = poly_unshift(c, key)
        if filt2(p):
            solves.append((key, p))
    return solves

## Decrypt a mono-byte shifted ciphertext
def byte_unshift(c,n):
    return byte_shift(c,-n)

## Index-based polyalphabetic transpositional encoding
def byte_rainbow(c):
    return ''.join([chr((ord(c[i])+i) % 255) for i in range(len(c))])

## Decode above
def byte_rev_rainbow(c):
    return ''.join([chr((ord(c[i])-i) % 255) for i in range(len(c))])

## Rough fitness test for determining
## whether input is like english text.
def is_english(c):
    matches = list()
    for word in WORDS:
        if len(word) >= 3 and word not in matches:
            if " {}".format(word) in c or "{} ".format(word) in c:
                matches.append(word)
        if len(matches) == 3:
            return True
    return False

## Returns the file(1) magic bytes
## determination.
def whatfile(d):
    with magic.Magic() as m:
        return m.id_buffer(d)

## Find likely XOR keys, with
## plaintext key type fitness test
def find_xor_keys(c, n, filt):
    keys = itertools.product(map(lambda x: chr(x), range(255)), repeat=n)
    possible_keys = list()
    for key in keys:
        key = ''.join(key)
        p = xor_repeat(c, key)
        if filt(p):
            possible_keys.append(key)
    return possible_keys

## Brute force XOR repeating cipher
## filt1 and filt2 are the first period
## and full ciphertext filters for speeding
## brute force time.
def brute_xor_repeat(c, n, filt1, filt2):
    keys = find_xor_keys(c[:n], n, filt1)
    solves = list()
    for key in keys:
        p = xor_repeat(c, key)
        if filt2(p):
            solves.append((key, p))
    return solves

## Brute force a monoalphabetic
## XOR ciphertext.
## filt is a filtering function for solves
def brute_xor_c(c, filt):
    if filt == None:
        raise Exception("A filter must be specified")
    solves = list()
    for key in range(255):
        key = chr(key)
        p = xor_c(c, key)
        if filt(p):
            solves.append((key, p))
    return solves

## Brute force mono-byte transpositional cipher
## filt is a user provided fitness test with signature
## func(d) where d is the decrypted candidate.
def brute_byte_shift(c, filt):
    if file == None:
        raise Exception("A filter must be provided")
    keys = range(255)
    solves = list()
    for key in keys:
        p = byte_shift(c, key)
        if filt(p):
            solves.append((key, p))
    return solves

## As above but in reverse
def brute_byte_unshift(c, filt):
    if filt == None:
        raise Exception("A filter must be provided")
    keys = range(255)
    solves = list()
    for key in keys:
        p = byte_unshift(c, key)
        if filt(p):
            solves.append(p)
    return solves

## Find ngrams in a text or ciphertext
def find_ngrams(c, n, count=1):
    return Counter(ngrams(c, n)).most_common(count)

## Perform Vernam OTP cipher
def vernam(p, k):
    if len(p) != len(k):
        raise Exception("Keystream must be equal in length to plaintext")
    return ''.join([chr(ord(p[i]) ^ ord(k[i])) for i in range(len(p))])

## Return whether input is an american english
## word.
def is_word(d):
    if d in WORDS and d not in BAD_WORDS:
            return True
    return False

## Return whether an english word starts
## with given string.
def word_starts_with(w):
    return len(filter(lambda x: x[:len(w)] == w, WORDS)) > 0

## Return an array a string
def the(d):
    return ''.join(d)

def possible_keys():
    return map(lambda x: ord(x), list(string.printable))

## Attempt to find words recursively in a vernam
## ciphertext.
def vernam_find_word(c, word=list()):
    for pkey in possible_keys():
        pc = chr(ord(c[0]) ^ pkey)
        if pc in list(string.ascii_letters + string.punctuation + ' '):
            word.append(pc)
            if word_starts_with(the(word)):
                if is_word(the(word)):
                    return word
                else:
                    if word_starts_with(the(word)):
                        return vernam_find_word(c[1:], word)
            else:
                word.pop()
                continue
    print "Reached end with no key for byte: {}".format(hexlify(c[0]))

##
# Try to break vernam by finding individual
# plaintext words in the ciphertext.
def break_vernam(c):
    bad_words = list()
    text = list()
    while len(the(text)) < len(c):
        word = vernam_find_word(c[len(the(text)):])
        text = text + word
    return the(text)

## Extract Vigenere columns
def v_column(c, n):
    if len(c) % n != 0:
        return None
    columns = list()
    for i in range(n):
        columns.append([c[x+i] for x in range(0,len(c),n)])
    return columns

## String made up of only printable characters
def printable(d):
    for i in list(d):
        if i not in list(string.printable):
            return False
    return True

## Contains only ascii, with simple punctuation
def just_text(d):
    for i in list(d):
        if i not in list(string.ascii_letters + '_' + ' ' + "'" + "?"):
            return False
    return True

## Use known plaintext to discover
## a partial keystream.
def discover_pt(c, p, tech, filt=None):
    if tech == None:
        raise Exception("A technique function with the signature func(c, k) must be specified")
    possible_keys = list()
    for i in range(len(c)):
        sample = c[i:i+len(p)]
        plain_sample = tech(sample, p)
        possible_keys.append(plain_sample)
    if filt != None:
        possible_keys = filter(filt, possible_keys)
    return possible_keys

## Implement the atbash cipher on the
## byte alphabet.
def byte_atbash(c):
    key1 = range(255,-1,-1)
    key2 = range(256)
    return ''.join([chr(key2[key1.index(ord(c[i]))]) for i in range(len(c))])

