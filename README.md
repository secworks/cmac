cmac
====
## Introduction ##
Verilog implementation of the block cipher based keyed hash function
CMAC. CMAC is specified in the NIST document
[SP 800-38 B](http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf)
and used in [RFC 4493](https://tools.ietf.org/html/rfc4493). Wikipedia has [a good summary of CMAC too.](https://en.wikipedia.org/wiki/One-key_MAC)

This implementation uses the
[AES block cipher](https://github.com/secworks/aes) with support for 128
and 256 bit keys. The ICV generated is 128 bit.


## Status ##
The core has been implemented and verified againt test vectors from IETF
and NIST using testbench for testcases with zero, single and multiple
block messages. Padding has been verified. The CMAC ICV generation works
with 128 or 256 bit keys.

The Core has been implemented in hardware (Altera and Xilinx FPGAs).


## Functionality ##
The core accepts a key and a message divided into zero, one or more 128
bit blocks. After processing the core provides a result, the Integrity
Check Vector (ICV) for the message. The ICV can be communicated to a
recipient. By recalculating the ICV for the received message and
comparing to the received ICV, the recipient can verify the message
integrity and that it is from a sender that share the secret key with
the recipient.

Performance wise, the cost of processing a message requires one initial
AES operation (for internal subkey generation) and then one AES
operation for each message block.


## Usage ##
The core is used by first writing the key into the key registers and
then asserting the _init_ control signal. When the core signals _ready_
the cmac has been initialized. Note that _valid_ will be deasserted by
the core, signalling that the ICV result is no longer valid.

The message can then be processed as a sequence of 128 bit blocks. For
each block the _next_ control signal shall be asserted. Note that
_ready_ signal must be set by the core for the core to accept new
blocks.

Note that the core expects information about number of bits in the final
message block [1..128]. The core performs padding and tweak based on
this information. The final block and the lenght shall be written to the
core and then the _finalize_ signal shall be asserted. The core will
process the final block and then raise _ready_ and _valid_ signalling
that the ICV result is ready and valid.

Note that the core does not provide verification of a given ICV. The
caller is expected to perform this comparison after generating the ICV
for a received message.


## Implementation Results ##
### Altera Cyclone V ###
- Device: 5CGXFC7C7F23C8
- Logic utilization (ALMs): 2285
- Registers:                3171
- Clock speed:              91 MHz


### Xilinx Artix-7 ###
- Device: xc7a200t-3fbg484
- Slices:    2721
- Registers: 2996
- Clock speed: 91 MHz


### Xilinx Spartan-6 ###
- Device: xc6slx45-3fgg484
- Slices:    2385
- Registers: 3002
- Clock speed: 100 MHz
