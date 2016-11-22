#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# cmac.py
# ------
# Simple, pure Python, CMAC implementation using the
# word based model of the AES cipher withsupport for 128 and
# 256 bit keys.
#
#
# Author: Joachim Strömbergson
# Copyright (c) 2016, Secworks Sweden AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys

# Note this assumes that the aes implementation is either in the
# same dir or symlinked.
from aes import *


#-------------------------------------------------------------------
# Constants.
#-------------------------------------------------------------------
VERBOSE = True
R128 = (0x00000000, 0x00000000, 0x00000000, 0x10000111)
MAX128 = ((2**128) - 1)

#-------------------------------------------------------------------
#-------------------------------------------------------------------
def xor_words(a, b):
    return (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3])

#-------------------------------------------------------------------
# shift_words
#-------------------------------------------------------------------
def shift_words(wl):
    print("wl:")
    print_block(wl)
    w = ((wl[0] << 96) + (wl[1] << 64) + (wl[2] << 32) + wl[3]) & MAX128
    print("w:  0x%032x" % w)
    ws = w << 1 & MAX128
    print("ws: 0x%032x" % ws)
    return ((ws >> 96) & 0xffffffff, (ws >> 64) & 0xffffffff,
            (ws >> 32) & 0xffffffff, ws & 0xffffffff)


#-------------------------------------------------------------------
# cmac()
#
# Notation follows the description in SP 800-38B
#-------------------------------------------------------------------
def cmac(key, message):
    # Start by generating the subkeys
    L = aes_encipher_block(key, (0, 0, 0, 0))
    print("Result from zero block encryption:")
    print_block(L)

    # Calculating the k1 and k2 tweak keys.
    MSBL = (L[0] >> 31) & 0x01
    print("MSBL = 0x%01x" % MSBL)
    if MSBL:
        K1 = xor_words(shift_words(L), R128)
    else:
        K1 = shift_words(L)
    print("K1:")
    print_block(K1)
    print()

    MSBK1 = (K1[0] >> 31) & 0x01
    print("MSBK1 = 0x%01x" % MSBK1)
    if MSBK1:
        K2 = xor_words(shift_words(K1), R128)
    else:
        K2 = shift_words(K1)
    print("K2:")
    print_block(K2)
    print()


#-------------------------------------------------------------------
# test_cmac()
#
# Test the CMAC implementation with NIST test vectors from:
# http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CMAC.pdf
#-------------------------------------------------------------------
def test_cmac():
    nist_key128 = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
    message = ""
    cmac(nist_key128, message)


#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the CMAC-AES mode")
    print("=========================")
    print

    test_cmac()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF aes_key_gen.py
#=======================================================================
