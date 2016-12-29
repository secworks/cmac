#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# test.py
# -------
# Test of CMAC module.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys
from pycmac import CMAC
from Crypto.Cipher import AES


#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the PyCrypto CMAC")
    print("=========================")
    print

    secret = b'Sixteen byte key'
    cobj = CMAC(secret, ciphermod=AES)
    cobj.update(b'Hello')
    print(cobj.hexdigest())


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
