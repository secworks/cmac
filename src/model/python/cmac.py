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
from aes import AES


#-------------------------------------------------------------------
# CMAC
#-------------------------------------------------------------------
class CMAC():
    VERBOSE = False
    R128 = (0, 0, 0, 0x00000087)
    MAX128 = ((2**128) - 1)
    AES_BLOCK_LENGTH = 128


    #-------------------------------------------------------------------
    #-------------------------------------------------------------------
    def __init__(self, verbose = True):
        self.VERBOSE = verbose
        self.my_aes = AES()

    #-------------------------------------------------------------------
    # check_block()
    #
    # Check and report if a result block matches expected block.
    #-------------------------------------------------------------------
    def check_block(self, expected, result):
        if (expected[0] == result[0]) and  (expected[1] == result[1]) and\
          (expected[2] == result[2]) and  (expected[3] == result[3]):
            print("OK. Result matches expected.")
        else:
            print("ERROR. Result does not match expected.")
            print("Expected:")
            self.my_aes.print_block(expected)
            print("Got:")
            self.my_aes.print_block(result)
            print("")


    #-------------------------------------------------------------------
    # xor_words()
    #-------------------------------------------------------------------
    def xor_words(self, a, b):
        c = (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3])
        if (self.VERBOSE):
            print("XORing words in the following two 128 bit block gives the result:")
            self.my_aes.print_block(a)
            self.my_aes.print_block(b)
            self.my_aes.print_block(c)
        return c


    #-------------------------------------------------------------------
    # shift_words()
    #-------------------------------------------------------------------
    def shift_words(self, wl):
        w = ((wl[0] << 96) + (wl[1] << 64) + (wl[2] << 32) + wl[3]) & self.MAX128
        ws = w << 1 & self.MAX128
        return ((ws >> 96) & 0xffffffff, (ws >> 64) & 0xffffffff,
                (ws >> 32) & 0xffffffff, ws & 0xffffffff)


    #-------------------------------------------------------------------
    # pad_block()
    #
    # Pad a given block with the "1000...." paddning as given by the
    # bitlen. Note that bitlen is assumed to be in the
    # range [0..127]
    #-------------------------------------------------------------------
    def pad_block(self, block, bitlen):
        bw = ((block[0] << 96) + (block[1] << 64) +
              (block[2] << 32) + block[3]) & self.MAX128
        bitstr = "1" * bitlen + "0" * (128 - bitlen)
        bitmask = int(bitstr, 2)
        masked = bw & bitmask
        padded = masked + (1 << (127 - bitlen))
        padded_block = ((padded >> 96) & 0xffffffff, (padded >> 64) & 0xffffffff,
                        (padded >> 32) & 0xffffffff, padded & 0xffffffff)
        return padded_block


    #-------------------------------------------------------------------
    # cmac_gen_subkeys()
    #
    # Generate subkeys K1 and K2.
    #-------------------------------------------------------------------
    def cmac_gen_subkeys(self, key):
        L = self.my_aes.aes_encipher_block(key, (0, 0, 0, 0))

        Pre_K1 = self.shift_words(L)
        MSBL = (L[0] >> 31) & 0x01
        if MSBL:
            K1 = self.xor_words(Pre_K1, self.R128)
        else:
            K1 = Pre_K1

        Pre_K2 = self.shift_words(K1)
        MSBK1 = (K1[0] >> 31) & 0x01
        if MSBK1:
            K2 = self.xor_words(Pre_K2, self.R128)
        else:
            K2 = Pre_K2

        if (self.VERBOSE):
            print("Internal data during sub key generation")
            print("---------------------------------------")
            print("L:")
            self.my_aes.print_block(L)

            print("MSBL = 0x%01x" % MSBL)
            print("Pre_K1:")
            self.my_aes.print_block(Pre_K1)
            print("K1:")
            self.my_aes.print_block(K1)
            print("MSBK1 = 0x%01x" % MSBK1)
            print("Pre_K2:")
            self.my_aes.print_block(Pre_K2)
            print("K2:")
            self.my_aes.print_block(K2)
            print()

        return (K1, K2)


    #-------------------------------------------------------------------
    # cmac()
    #
    # Notation follows the description in SP 800-38B. Message is in
    # blocks and final_length is number of bits in the final block
    #-------------------------------------------------------------------
    def cmac(self, key, message, final_length):

        # Start by generating the subkeys
        (K1, K2) = self.cmac_gen_subkeys(key)
        print("Subkeys generated.")
        state = (0x00000000, 0x00000000, 0x00000000, 0x00000000)
        blocks = len(message)

        if blocks == 0:
            # Empty message.
            paddded_block = self.pad_block(state, 0)
            tweak = self.xor_words(paddded_block, K2)
            print("tweak empty block")
            self.my_aes.print_block(tweak)
            M = self.my_aes.aes_encipher_block(key, tweak)

        else:
            for i in range(blocks - 1):
                state = self.xor_words(state, message[i])
                print("state before aes block %d:" % (i + 1))
                self.my_aes.print_block(state)
                state = self.my_aes.aes_encipher_block(key, state)
                print("state after aes block %d:" % (i + 1))
                self.my_aes.print_block(state)

            if (final_length == self.AES_BLOCK_LENGTH):
                tweak = self.xor_words(K1, message[-1])
                print("tweak complete final block")
                self.my_aes.print_block(tweak)

            else:
                padded_block = self.pad_block(message[- 1], final_length)
                tweak = self.xor_words(K2, padded_block)
                print("tweak incomplete final block")
                self.my_aes.print_block(tweak)

        state = self.xor_words(state, tweak)
        print("state before aes final block:")
        self.my_aes.print_block(state)
        M = self.my_aes.aes_encipher_block(key, state)
        print("state after aes final block:")
        self.my_aes.print_block(M)

        return M


    #-------------------------------------------------------------------
    # test_xor()
    #-------------------------------------------------------------------
    def test_xor(self):
        print("*** Testing XOR words ***")
        a = (0x00000000, 0x55555555, 0xaaaaaaaa, 0xff00ff00)
        b = (0xdeadbeef, 0xaa00aa00, 0x55555555, 0xffffffff)
        c = self.xor_words(a , b)
        self.my_aes.print_block(c)


    #-------------------------------------------------------------------
    # test_cmac_subkey_gen()
    #
    # Test the subkey functionality by itself. Testvectors are
    # from the first examples in NISTs test case suite.
    #-------------------------------------------------------------------
    def test_cmac_subkey_gen(self):
        nist_key128 = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
        nist_exp_k1 = (0xfbeed618, 0x35713366, 0x7c85e08f, 0x7236a8de)
        nist_exp_k2 = (0xf7ddac30, 0x6ae266cc, 0xf90bc11e, 0xe46d513b)

        (K1, K2) = self.cmac_gen_subkeys(nist_key128)

        print("*** Testing CMAC subkey generation ***")
        print("Checking key K1")
        self.check_block(K1, nist_exp_k1)
        print("Checking key K2")
        self.check_block(K2, nist_exp_k2)


    #-------------------------------------------------------------------
    # test_zero_length_message()
    #
    # Test final tweak.
    #-------------------------------------------------------------------
    def test_zero_length_message(self):
        print("Testing cmac of block with zero length:")
        print("---------------------------------------")
        key = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
        final_block = (0x00000000, 0x00000000, 0x00000000, 0x00000000)
        k2 = (0xf7ddac30, 0x6ae266cc, 0xf90bc11e, 0xe46d513b)

        paddded_block = self.pad_block(final_block, 0)
        tweak = self.xor_words(paddded_block, k2)
        M = self.my_aes.aes_encipher_block(key, tweak)
        print("padded final block")
        self.my_aes.print_block(paddded_block)
        print("tweak empty block")
        self.my_aes.print_block(tweak)

        expected = (0xbb1d6929, 0xe9593728, 0x7fa37d12, 0x9b756746)
        self.check_block(expected, M)
        print()


    #-------------------------------------------------------------------
    # test_padding()
    #-------------------------------------------------------------------
    def test_padding(self):
        print("Testing padding of block based on number of data bits in block:")
        print("---------------------------------------------------------------")
        block = (0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
        for num_bits in range(128):
            padded = self.pad_block(block, num_bits)
            print("num bits: %03d" % num_bits, end=": ")
            self.my_aes.print_block(padded)
            print()


    #-------------------------------------------------------------------
    # test_final()
    #
    # Test final tweak.
    #-------------------------------------------------------------------
    def test_final(self):
        print("Testing final block. Basically an empty message:")
        key = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
        final_block = (0x80000000, 0x00000000, 0x00000000, 0x00000000)
        k2 =          (0xf7ddac30, 0x6ae266cc, 0xf90bc11e, 0xe46d513b)
        tweaked_final = self.xor_words(final_block, k2)
        M = self.my_aes.aes_encipher_block(key, tweaked_final)
        expected = (0xbb1d6929, 0xe9593728, 0x7fa37d12, 0x9b756746)
        self.check_block(expected, M)


    #-------------------------------------------------------------------
    # test_cmac()
    #-------------------------------------------------------------------
    def test_cmac(self):
        print("Testing complete cmac:")
        print("----------------------")

        # 128 bit key tests.
        nist_key128  = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
        print("128 bit key, zero length message.")
        expect_1_128 = (0xbb1d6929, 0xe9593728, 0x7fa37d12, 0x9b756746)
        message = []
        final_length = 0
        result = self.cmac(nist_key128, message, final_length)
        self.check_block(expect_1_128, result)
        print("")


        print("128 bit key, one block message.")
        expect_2_128 = (0x070a16b4, 0x6b4d4144, 0xf79bdd9d, 0xd04a287c)
        message = [(0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a)]
        final_length = 128
        result = self.cmac(nist_key128, message, final_length)
        self.check_block(expect_2_128, result)
        print("")


        print("128 bit key, one and a quart message.")
        expect_3_128 = (0x7d85449e, 0xa6ea19c8, 0x23a7bf78, 0x837dfade)
        message = [(0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a),
                   (0xae2d8a57, 0x00000000, 0x00000000, 0x00000000)]
        final_length = 32
        result = self.cmac(nist_key128, message, final_length)
        self.check_block(expect_3_128, result)
        print("")


        print("128 bit key, four block message.")
        expect_4_128 = (0x51f0bebf, 0x7e3b9d92, 0xfc497417, 0x79363cfe)
        message = [(0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a),
                   (0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51),
                   (0x30c81c46, 0xa35ce411, 0xe5fbc119, 0x1a0a52ef),
                   (0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710)]
        final_length = 128
        result = self.cmac(nist_key128, message, final_length)
        self.check_block(expect_4_128, result)
        print("")


        # 256 bit key tests.
        nist_key256 = (0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                       0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4)
        print("256 bit key, zero length message.")
        expect_1_256 = (0x028962f6, 0x1b7bf89e, 0xfc6b551f, 0x4667d983)
        message = []
        final_length = 0
        result = self.cmac(nist_key256, message, final_length)
        self.check_block(expect_1_256, result)


        print("256 bit key, four block message.")
        expect_2_256 = (0xe1992190, 0x549f6ed5, 0x696a2c05, 0x6c315410)
        message = [(0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a),
                   (0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51),
                   (0x30c81c46, 0xa35ce411, 0xe5fbc119, 0x1a0a52ef),
                   (0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710)]
        final_length = 128
        result = self.cmac(nist_key256, message, final_length)
        self.check_block(expect_2_256, result)


    #-------------------------------------------------------------------
    # run_test()
    #
    # If executed tests the cmac function and its subfunctions.
    #-------------------------------------------------------------------
    def run_tests(self):
        print("Testing the CMAC-AES mode")
        print("=========================")
        print()

        self.test_xor()
        self.test_cmac_subkey_gen()
        self.test_final()
        self.test_padding()
        self.test_zero_length_message()
        self.test_cmac()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    my_cmac = CMAC()
    sys.exit(my_cmac.run_tests())

#=======================================================================
# EOF cmac.py
#=======================================================================
