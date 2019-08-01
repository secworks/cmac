#===================================================================
#
# Makefile
# --------
# Makefile for building the cmac.
#
#
# Author: Joachim Strombergson
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
#===================================================================

# AES sources needed.
AES_CORE_SW_DIR=../../aes/src/rtl
SBOX_SRC=$(AES_CORE_SW_DIR)/aes_sbox.v
INV_SBOX_SRC=$(AES_CORE_SW_DIR)/aes_inv_sbox.v
KEYMEM_SRC=$(AES_CORE_SW_DIR)/aes_key_mem.v
ENCIPHER_SRC=$(AES_CORE_SW_DIR)/aes_encipher_block.v
DECIPHER_SRC=$(AES_CORE_SW_DIR)/aes_decipher_block.v
AES_CORE_SRC=$(AES_CORE_SW_DIR)/aes_core.v $(KEYMEM_SRC) $(SBOX_SRC) $(INV_SBOX_SRC) $(ENCIPHER_SRC) $(DECIPHER_SRC)


CORE_SRC=../src/rtl/cmac_core.v $(AES_CORE_SRC)
TB_CORE_SRC =../src/tb/tb_cmac_core.v


TOP_SRC=../src/rtl/cmac.v $(CORE_SRC)
TB_TOP_SRC =../src/tb/tb_cmac.v


PADDING_SRC=../src/model/verilog/cmac_padding.v


CC = iverilog
CC_FLAGS = -Wall

LINT = verilator
LINT_FLAGS = +1364-2001ext+ --lint-only  -Wall -Wno-fatal -Wno-DECLFILENAME


all: padding.sim top.sim core.sim


top.sim: $(TB_TOP_SRC) $(TOP_SRC)
	$(CC) $(CC_FLAGS) -o top.sim $(TB_TOP_SRC) $(TOP_SRC)


core.sim: $(TB_CORE_SRC) $(CORE_SRC)
	$(CC) $(CC_FLAGS) -o core.sim $(TB_CORE_SRC) $(CORE_SRC)


padding.sim: $(PADDING_SRC)
	$(CC) $(CC_FLAGS) -o padding.sim $(PADDING_SRC)


sim-top: top.sim
	./top.sim


sim-core: core.sim
	./core.sim


sim-padding: padding.sim
	./padding.sim


lint: $(TOP_SRC)
	$(LINT) $(LINT_FLAGS) $(TOP_SRC)


clean:
	rm -f top.sim
	rm -f core.sim
	rm -f padding.sim


help:
	@echo "Build system for simulation of AES CMAC Verilog core"
	@echo ""
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:          Build all simulation targets."
	@echo "lint:         Lint all rtl source files."
	@echo "top.sim:      Build top level simulation target."
	@echo "core.sim:     Build core level simulation target."
	@echo "padding.sim:  Build padding target."
	@echo "sim-top:      Run top level simulation."
	@echo "sim-core:     Run core level simulation."
	@echo "sim-padding:  Run padding simulation."
	@echo "clean:        Delete all built files."

#===================================================================
# EOF Makefile
#===================================================================
