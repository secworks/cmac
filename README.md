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
The core accepts a key and a message divided into zero, one or more 128
bit blocks. After processing the core provides a result, the Integrity
Check Vector (ICV) for the message. The ICV can be communicated to a
recipient. By recalculating the ICV for the received message and
comparing to the received ICV, the recipient can verify the message
integrity and that it is from a sender that share the secret key with
the recipient.

Performance wise, the cost of processing a message requires one initial
AES operation (for internal subkey generation) and then one AES
operation for each block.


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
process the final block and then rainse _ready_ and _valid_ signalling
that the ICV result is ready and valid.


## Implementation Results ##
### Altera Cyclone V ###
Device: 5CGXFC7C7F23C8
Logic utilization (ALMs): 2105
Registers:                3052
Clock speed:              99 MHz

### Xilinx ###
TODO: Add implementation results for Spartan-6 and Artix-7.


## Status ##
- Core has been verified againt test vectors from IETF and NIST.
- Core has been implemented in hardware (Altera FPGA).
- Testbench has been completed

- Python model is working but not complete and needs cleanup.
- Some cleanup in RTL code still needed.
