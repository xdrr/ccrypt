# Ccrypt

A python library implementation of some classical cipher primitives and cryptanalysis functions.

Current ccrypt only works on GNU Linux systems.

## SYNOPSIS

To access all functions availble in the library, simply import them all by wildcard.

```python
from ccrypt import *
```

## What's it good for?

This project might be useful for CTFs using simple transposition and substitution ciphers.

## Examples

Discover partial key in a repeating XOR cipher:

```python
>>> from ccrypt import *
>>> c = xor_repeat("This is a simple test message", "TEST")
>>> c
"\x00-:'t, t5e =95?1t16' e>1'6231"
>>> discover_pt(c, "simple", xor_repeat)
['sDWW\x18I', '^SJ\x04@E', 'IN\x19\\L\x11', 'T\x1dAP\x18P', '\x07EM\x04Y\x00', '_I\x19E\tE', 'S\x1dX\x15LX', '\x07\\\x08PQ\\', 'F\x0cMMUP', '\x16IPIYZ', 'STTEST', 'NPXO]\x11', 'J\\RA\x18T', 'FV\\\x04]S', 'LX\x19AZB', 'B\x1d\\FKE', '\x07X[WL\x00', 'B_JP\t[', 'ENM\x15RT', 'TI\x08N]B', 'S\x0cSAKS', '\x16W\\WZW', 'MXJF^V', 'BN[B_T', 'T__C]', 'E[^A', 'AZ\\', '@X', 'B']
>>>
```

Use monoalphabetic or repeating XOR ciphers.

```python
>>> xor_repeat("This is kind of cool", "SEC")
"\x07-* e* e(:+'s*%s&,<)"
>>> xor_repeat(xor_repeat("This is kind of cool", "SEC"), "SEC")
'This is kind of cool'
>>> xor_c("Only a single character for this one", "F")
"\t(*?f'f5/(!*#f%.'4'%2#4f )4f2./5f)(#"
>>>
```

Use a polyalphabetic transposition cipher:

```python
>>> poly_shift("Just shifting about.", "KEY")
'\x95\xba\xcc\xbfe\xcc\xb3\xae\xbf\xbf\xae\xc7\xb2e\xba\xad\xb4\xce\xbfs'
>>> poly_unshift(poly_shift("Just shifting about.", "KEY"), "KEY")
'Just shifting about.'
>>>
```

Brute force a XOR repeating cipher:

```python
>>> c = xor_repeat("Just a simple plaintext message", "KEY")
>>> c
"\x010*?e8k60&55.e)'$0%1<31y& *8$>."
>>> brute_xor_repeat(c, 3, just_text, just_text)
Just a simple plaintext message
[('KEY', 'Just a simple plaintext message')]
```

Find candidate polyalphabetic transpositional keys:

```python
>>> c = poly_shift("What's the go?", "KEY")
>>> find_poly_keys(c, 3, just_text)
['KER', 'KES', 'KET', 'KEU', 'KEV', 'KEW', 'KEX', 'KEY', 'KE[', 'KEg', 'KEh', 'KEi', 'KEj', 'KEk', 'KEm', 'KEr', 'KEs', 'KEt', 'KEu', 'KEv', 'KEw', 'KEx', 'KEy', 'KE{']
>>>
```

Use some simple fitness tests:

```python
>>> is_english("What say you?")
True
>>> c = xor_repeat("Super secret message", "KEY")
>>> is_english(c)
False
>>> is_english("{}{J(*J_F#(_@HF")
False
>>>
>>> just_text("Just some text__")
True
>>> just_text("Just some text_()_#JF}_!(FHJ_")
False
>>>
```

Easily determine decrypted content's file type:

```python
>>> whatfile("\x7fELF\x02")
'ELF 64-bit'
```

Find ngrams in ciphertext and plaintext:

```python
>>> c = xor_repeat("Can you guess the key length here over this very long piece of text which should help you find a cooincidence of plain and key repetition.", "XYZ")
>>> find_ngrams(c, 3, 5)
[(('#', 'x', '5'), 2), ((',', '=', '+'), 2), (('3', '<', '#'), 2), (('z', '3', '<'), 2), (('<', '#', 'x'), 2)]
>>>
```

Read `ccrypt.py` for a full list of functions.

## LICENSE

The project and its content are licensed under GPLv3. No warranty is
given for its use and the author takes no responsibilty for its misuse.
