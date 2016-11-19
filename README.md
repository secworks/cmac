cmac
====
Verilog implementation of the block cipher bases keyed hash function
CMAC. CMAC is specified in the NIST document
[SP 800-38 B](http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf). Wikipedia
has [a good summary of CMAC too.](https://en.wikipedia.org/wiki/One-key_MAC)

This implementation use the
[AES block cipher](https://github.com/secworks/aes) with support for 128
and 256 bit keys. The ICV generated is 128 bit.


## Status ##
Core just started.
