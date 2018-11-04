//======================================================================
//
// cmac_core.v
// -----------
// CMAC based on AES. Support for 128 and 256 bit keys. Generates
// 128 bit MAC. The core is compatible with NIST SP 800-38 B and
// as used in RFC 4493.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2018, Secworks Sweden AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module cmac_core(
                 input wire            clk,
                 input wire            reset_n,

                 input wire [255 : 0]  key,
                 input wire            keylen,

                 input wire [7 : 0]    final_size,

                 input wire            init,
                 input wire            next,
                 input wire            finalize,

                 input wire [127 : 0]  block,

                 output wire [127 : 0] result,
                 output wire           ready,
                 output wire           valid
                );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam BMUX_ZERO        = 0;
  localparam BMUX_MESSAGE     = 1;
  localparam BMUX_TWEAK       = 2;

  localparam CTRL_IDLE        = 0;
  localparam CTRL_INIT_CORE   = 1;
  localparam CTRL_GEN_SUBKEYS = 2;
  localparam CTRL_NEXT_BLOCK  = 3;
  localparam CTRL_FINAL_BLOCK = 4;

  localparam R128 = {120'h0, 8'b10000111};
  localparam AES_BLOCK_SIZE = 128;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [127 : 0] result_reg;
  reg [127 : 0] result_new;
  reg           result_we;
  reg           reset_result_reg;
  reg           update_result_reg;

  reg           valid_reg;
  reg           valid_new;
  reg           valid_we;
  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [127 : 0] k1_reg;
  reg [127 : 0] k1_new;
  reg [127 : 0] k2_reg;
  reg [127 : 0] k2_new;
  reg           k1_k2_we;

  reg [3 : 0]   cmac_ctrl_reg;
  reg [3 : 0]   cmac_ctrl_new;
  reg           cmac_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            aes_init;
  reg            aes_next;
  wire           aes_encdec;
  wire           aes_ready;
  reg  [127 : 0] aes_block;
  wire [127 : 0] aes_result;
  wire           aes_valid;

  reg [1 : 0]    bmux_ctrl;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign aes_encdec = 1'h1;

  assign result = result_reg;
  assign ready  = ready_reg;
  assign valid  = valid_reg;


  //----------------------------------------------------------------
  // AES core instantiation.
  //----------------------------------------------------------------
  aes_core aes_inst(
                    .clk(clk),
                    .reset_n(reset_n),

                    .encdec(aes_encdec),
                    .init(aes_init),
                    .next(aes_next),
                    .ready(aes_ready),

                    .key(key),
                    .keylen(keylen),

                    .block(aes_block),
                    .result(aes_result),
                    .result_valid(aes_valid)
                   );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin : reg_update
      if (!reset_n)
        begin
          k1_reg         <= 128'h0;
          k2_reg         <= 128'h0;
          result_reg     <= 128'h0;
          valid_reg      <= 1'h0;
          ready_reg      <= 1'h1;
          cmac_ctrl_reg  <= CTRL_IDLE;
        end
      else
        begin
          if (result_we)
            result_reg <= result_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (valid_we)
            valid_reg <= valid_new;

          if (k1_k2_we)
            begin
              k1_reg <= k1_new;
              k2_reg <= k2_new;
            end

          if (cmac_ctrl_we)
            cmac_ctrl_reg <= cmac_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // cmac_datapath
  //
  // The cmac datapath. Basically a mux for the input data block
  // to the AES core and some gates for the logic.
  //----------------------------------------------------------------
  always @*
    begin : cmac_datapath
      reg [127 : 0] mask;
      reg [127 : 0] masked_block;
      reg [127 : 0] padded_block;
      reg [127 : 0] tweaked_block;

      result_new = 128'h0;
      result_we  = 0;

      // Handle result reg updates and clear
      if (reset_result_reg)
        result_we  = 1'h1;

      if (update_result_reg)
        begin
          result_new = aes_result;
          result_we  = 1'h1;
        end

      // Generation of subkey k1 and k2.
      k1_new = {aes_result[126 : 0], 1'b0};
      if (aes_result[127])
        k1_new = k1_new ^ R128;

      k2_new = {k1_new[126 : 0], 1'b0};
      if (k1_new[127])
        k2_new = k2_new ^ R128;


      // Padding of final block. We create a mask that preserves
      // the data in the block and zeroises all other bits.
      // We add a one to bit at the first non-data position.
      mask = 128'b0;

      if (final_size[0])
        mask = {1'b1, mask[127 :  1]};

      if (final_size[1])
        mask = {2'h3, mask[127 :  2]};

      if (final_size[2])
        mask = {4'hf, mask[127 :  4]};

      if (final_size[3])
        mask = {8'hff, mask[127 :  8]};

      if (final_size[4])
        mask = {16'hffff, mask[127 :  16]};

      if (final_size[5])
        mask = {32'hffffffff, mask[127 :  32]};

      if (final_size[6])
        mask = {64'hffffffff_ffffffff, mask[127 :  64]};

      masked_block = block & mask;
      padded_block = masked_block;
      padded_block[(127 - final_size[6 : 0])] = 1'b1;


      // Tweak of final block. Based on if the final block is full or not.
      if (final_size == AES_BLOCK_SIZE)
        tweaked_block = k1_reg ^ block;
      else
        tweaked_block = k2_reg ^ padded_block;


      // Input mux for the AES core.
      aes_block = 128'h0;
      case (bmux_ctrl)
        BMUX_ZERO:
          aes_block = 128'h0;

        BMUX_MESSAGE:
          aes_block  = result_reg ^ block;

        BMUX_TWEAK:
          aes_block  = result_reg ^ tweaked_block;
      endcase // case (bmux_ctrl)
    end


  //----------------------------------------------------------------
  // cmac_ctrl
  //
  // The FSM controlling the cmac functionality.
  //----------------------------------------------------------------
  always @*
    begin : cmac_ctrl
      aes_init          = 1'h0;
      aes_next          = 1'h0;
      bmux_ctrl         = BMUX_ZERO;
      reset_result_reg  = 1'h0;
      update_result_reg = 1'h0;
      k1_k2_we          = 1'h0;
      ready_new         = 1'h0;
      ready_we          = 1'h0;
      valid_new         = 1'h0;
      valid_we          = 1'h0;
      cmac_ctrl_new     = CTRL_IDLE;
      cmac_ctrl_we      = 1'h0;

      case (cmac_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                ready_new        = 1'h0;
                ready_we         = 1'h1;
                valid_new        = 1'h0;
                valid_we         = 1'h1;
                aes_init         = 1'h1;
                reset_result_reg = 1'h1;
                cmac_ctrl_new    = CTRL_INIT_CORE;
                cmac_ctrl_we     = 1'h1;
              end

            if (next)
              begin
                ready_new     = 1'h0;
                ready_we      = 1'h1;
                aes_next      = 1'h1;
                bmux_ctrl     = BMUX_MESSAGE;
                cmac_ctrl_new = CTRL_NEXT_BLOCK;
                cmac_ctrl_we  = 1'h1;
              end

            if (finalize)
              begin
                ready_new     = 1'h0;
                ready_we      = 1'h1;
                aes_next      = 1'h1;
                bmux_ctrl     = BMUX_TWEAK;
                cmac_ctrl_new = CTRL_FINAL_BLOCK;
                cmac_ctrl_we  = 1'h1;
              end
          end

        CTRL_INIT_CORE:
          begin
            if (aes_ready)
              begin
                aes_next      = 1'h1;
                bmux_ctrl     = BMUX_ZERO;
                cmac_ctrl_new = CTRL_GEN_SUBKEYS;
                cmac_ctrl_we  = 1'h1;
              end
          end

        CTRL_GEN_SUBKEYS:
          begin
            if (aes_ready)
              begin
                ready_new     = 1'h1;
                ready_we      = 1'h1;
                k1_k2_we      = 1'h1;
                cmac_ctrl_new = CTRL_IDLE;
                cmac_ctrl_we  = 1'h1;
              end
          end

        CTRL_NEXT_BLOCK:
          begin
            bmux_ctrl = BMUX_MESSAGE;
            if (aes_ready)
              begin
                update_result_reg = 1'h1;
                ready_new         = 1'h1;
                ready_we          = 1'h1;
                cmac_ctrl_new     = CTRL_IDLE;
                cmac_ctrl_we      = 1'h1;
              end
          end

        CTRL_FINAL_BLOCK:
          begin
            bmux_ctrl = BMUX_TWEAK;
            if (aes_ready)
              begin
                update_result_reg = 1'h1;
                valid_new         = 1'h1;
                valid_we          = 1'h1;
                ready_new         = 1'h1;
                ready_we          = 1'h1;
                cmac_ctrl_new     = CTRL_IDLE;
                cmac_ctrl_we      = 1'h1;
              end
          end

        default:
          begin
          end
      endcase // case (cmac_ctrl_reg)
    end

endmodule // cmac_core

//======================================================================
// EOF cmac_core.v
//======================================================================
