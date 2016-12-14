cmac
====
Verilog implementation of the block cipher based keyed hash function
CMAC. CMAC is specified in the NIST document
[SP 800-38 B](http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf)
and used in [RFC 4493](https://tools.ietf.org/html/rfc4493). Wikipedia has [a good summary of CMAC too.](https://en.wikipedia.org/wiki/One-key_MAC)

This implementation uses the
[AES block cipher](https://github.com/secworks/aes) with support for 128
and 256 bit keys. The ICV generated is 128 bit.


## Functionality ##


## Usage ##
Note that the core expects information about number of bits in the final
message block [1..128]. The core performs padding and tweak based in
this information.


## Status ##
Core just started.
Python model being developed.
Testbench just started.
