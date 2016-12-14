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
# Test vectors used in the tests are from the NIST specification:
# http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CMAC.pdf
#
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
R128 = (0, 0, 0, 0x00000087)
MAX128 = ((2**128) - 1)


#-------------------------------------------------------------------
# xor_words()
#-------------------------------------------------------------------
def xor_words(a, b):
    c = (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3])
    if VERBOSE:
        print("XORing words in the following two 128 bit block gives the result:.")
        print_block(a)
        print_block(b)
        print_block(c)
    return c


#-------------------------------------------------------------------
# shift_words()
#-------------------------------------------------------------------
def shift_words(wl):
    w = ((wl[0] << 96) + (wl[1] << 64) + (wl[2] << 32) + wl[3]) & MAX128
    ws = w << 1 & MAX128
    return ((ws >> 96) & 0xffffffff, (ws >> 64) & 0xffffffff,
            (ws >> 32) & 0xffffffff, ws & 0xffffffff)


#-------------------------------------------------------------------
# cmac_gen_subkeys()
#-------------------------------------------------------------------
def cmac_gen_subkeys(key):
    L = aes_encipher_block(key, (0, 0, 0, 0))

    Pre_K1 = shift_words(L)
    MSBL = (L[0] >> 31) & 0x01
    if MSBL:
        K1 = xor_words(Pre_K1, R128)
    else:
        K1 = Pre_K1


    Pre_K2 = shift_words(K1)
    MSBK1 = (K1[0] >> 31) & 0x01
    if MSBK1:
        K2 = xor_words(Pre_K2, R128)
    else:
        K2 = Pre_K2

    if VERBOSE:
        print("Internal data during sub key generation")
        print("---------------------------------------")
        print("L:")
        print_block(L)

        print("MSBL = 0x%01x" % MSBL)
        print("Pre_K1:")
        print_block(Pre_K1)
        print("K1:")
        print_block(K1)
        print("MSBK1 = 0x%01x" % MSBK1)
        print("Pre_K2:")
        print_block(Pre_K2)
        print("K2:")
        print_block(K2)
        print()

    return (K1, K2)


#-------------------------------------------------------------------
# cmac()
#
# Notation follows the description in SP 800-38B
#-------------------------------------------------------------------
def cmac(key, message):
    # Start by generating the subkeys
    (K1, K2) = cmac_gen_subkeys(key)


#-------------------------------------------------------------------
# test_cmac()
#
#-------------------------------------------------------------------
def test_cmac():
    nist_key128  = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
    expect_1_128 = (0xbb1d6929, 0xe9593728, 0x7fa37d12, 0x9b756746)
    expect_2_128 = (0x070a16b4, 0x6b4d4144, 0xf79bdd9d, 0xd04a287c)
    expect_3_128 = (0x7d85449e, 0xa6ea19c8, 0x23a7bf78, 0x837dfade)
    expect_4_128 = (0x51f0bebf, 0x7e3b9d92, 0xfc497417, 0x79363cfe)

    nist_key256  = (0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                    0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4)
    expect_1_256 = (0x028962f6, 0x1b7bf89e, 0xfc6b551f, 0x4667d983)
    expect_2_256 = (0x28a7023f, 0x452e8f82, 0xbd4bf28d, 0x8c37c35c)
    expect_3_256 = (0x156727dc, 0x0878944a, 0x023c1fe0, 0x3bad6d93)
    expect_4_256 = (0xe1992190, 0x549f6ed5, 0x696a2c05, 0x6c315410)


    message = ""
    cmac(nist_key128, message)

#-------------------------------------------------------------------
# test_xor()
#-------------------------------------------------------------------
def test_xor():
    print("*** Testing XOR words ***")
    a = (0x00000000, 0x55555555, 0xaaaaaaaa, 0xff00ff00)
    b = (0xdeadbeef, 0xaa00aa00, 0x55555555, 0xffffffff)
    c = xor_words(a , b)
    print_block(c)


#-------------------------------------------------------------------
# test_cmac_subkey_gen()
#
# Test the subkey functionality by itself. Testvectors are
# from the first examples in NISTs test case suite.
#-------------------------------------------------------------------
def test_cmac_subkey_gen():
    nist_key128 = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
    nist_exp_k1 = (0xfbeed618, 0x35713366, 0x7c85e08f, 0x7236a8de)
    nist_exp_k2 = (0xf7ddac30, 0x6ae266cc, 0xf90bc11e, 0xe46d513b)

    (K1, K2) = cmac_gen_subkeys(nist_key128)

    print("*** Testing CMAC subkey generation ***")
    correct = True
    if (K1 != nist_exp_k1):
        correct = False
        print("Error in K1 subkey generation.")
        print("Expected:")
        print_block(nist_exp_k1)
        print("Got:")
        print_block(K1)

    if (K2 != nist_exp_k2):
        correct = False
        print("Error in K2 subkey generation.")
        print("Expected:")
        print_block(nist_exp_k2)
        print("Got:")
        print_block(K2)

    if correct:
        print("K1 and K2 subkey generation correct.")
    print()


#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the CMAC-AES mode")
    print("=========================")
    print

    test_xor()
    test_cmac_subkey_gen()
#    test_cmac()


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
