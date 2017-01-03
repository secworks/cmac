//======================================================================
//
// cmac.v
// ------
// CMAC based on AES. Support for 128 and 256 bit keys. Generates
// 128 bit MAC. The core is compatible with NIST SP 800-38 B and
// as used in RFC 4493.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2016, Secworks Sweden AB
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

module cmac(
            input wire           clk,
            input wire           reset_n,

            input wire           cs,
            input wire           we,
            input wire  [7 : 0]  address,
            input wire  [31 : 0] write_data,
            output wire [31 : 0] read_data
           );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0       = 8'h00;
  localparam ADDR_NAME1       = 8'h01;
  localparam ADDR_VERSION     = 8'h02;

  localparam ADDR_CTRL        = 8'h08;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;
  localparam CTRL_FINAL_BIT   = 2;

  localparam ADDR_CONFIG      = 8'h09;
  localparam CTRL_KEYLEN_BIT  = 0;

  localparam ADDR_STATUS      = 8'h0a;
  localparam STATUS_READY_BIT = 0;
  localparam STATUS_VALID_BIT = 1;

  localparam ADDR_FINAL_SIZE = 8'h0b;

  localparam ADDR_KEY0        = 8'h10;
  localparam ADDR_KEY7        = 8'h17;

  localparam ADDR_BLOCK0      = 8'h20;
  localparam ADDR_BLOCK1      = 8'h21;
  localparam ADDR_BLOCK2      = 8'h22;
  localparam ADDR_BLOCK3      = 8'h23;

  localparam ADDR_RESULT0     = 8'h30;
  localparam ADDR_RESULT1     = 8'h31;
  localparam ADDR_RESULT2     = 8'h32;
  localparam ADDR_RESULT3     = 8'h33;

  localparam CORE_NAME0       = 32'h636d6163; // "cmac"
  localparam CORE_NAME1       = 32'h2d616573; // "-aes"
  localparam CORE_VERSION     = 32'h302e3031; // "0.01"

  localparam BMUX_ZERO        = 0;
  localparam BMUX_MESSAGE     = 1;
  localparam BMUX_TWEAK       = 2;

  localparam CTRL_IDLE        = 0;
  localparam CTRL_INIT_CORE   = 1;
  localparam CTRL_GEN_SUBKEYS = 2;
  localparam CTRL_NEXT_BLOCK  = 3;
  localparam CTRL_FINAL_BLOCK = 4;
  localparam CTRL_DONE        = 5;

  localparam R128 = {120'h0, 8'b10000111};
  localparam AES_BLOCK_SIZE = 128;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg           keylen_reg;
  reg           config_we;

  reg [7 : 0]   final_size_reg;
  reg           final_size_we;

  reg [31 : 0]  block_reg [0 : 3];
  reg           block_we;

  reg [31 : 0]  key_reg [0 : 7];
  reg           key_we;

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
  reg [31 : 0]   tmp_read_data;

  reg            init;
  reg            next;
  reg            finalize;

  reg            core_init;
  reg            core_next;
  wire           core_encdec;
  wire           core_ready;
  wire [255 : 0] core_key;
  wire           core_keylen;
  reg  [127 : 0] core_block;
  wire [127 : 0] core_result;
  wire           core_valid;

  reg [1 : 0]    bmux_ctrl;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign read_data = tmp_read_data;

  assign core_key = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                     key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_encdec = 1'b1;
  assign core_keylen = keylen_reg;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_core core(
                .clk(clk),
                .reset_n(reset_n),

                .encdec(core_encdec),
                .init(core_init),
                .next(core_next),
                .ready(core_ready),

                .key(core_key),
                .keylen(core_keylen),

                .block(core_block),
                .result(core_result),
                .result_valid(core_valid)
               );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin : reg_update
      integer i;

      if (!reset_n)
        begin
          for (i = 0; i < 4; i = i + 1)
            block_reg[i] <= 32'h0;

          for (i = 0; i < 8; i = i + 1)
            key_reg[i] <= 32'h0;

          k1_reg         <= 128'h0;
          k2_reg         <= 128'h0;
          keylen_reg     <= 0;
          final_size_reg <= 8'h0;
          result_reg     <= 128'h0;
          valid_reg      <= 0;
          ready_reg      <= 1;
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

          if (config_we)
            begin
              keylen_reg <= write_data[CTRL_KEYLEN_BIT];
            end

          if (final_size_we)
            final_size_reg <= write_data[7 : 0];

          if (key_we)
            key_reg[address[2 : 0]] <= write_data;

          if (block_we)
            block_reg[address[1 : 0]] <= write_data;

          if (cmac_ctrl_we)
            cmac_ctrl_reg <= cmac_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  always @*
    begin : api
      init          = 0;
      next          = 0;
      finalize      = 0;
      final_size_we = 0;
      config_we     = 0;
      key_we        = 0;
      block_we      = 0;
      tmp_read_data = 32'h0;

      if (cs)
        begin
          if (we)
            begin
              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                key_we = 1;

              if ((address >= ADDR_BLOCK0) && (address <= ADDR_BLOCK3))
                key_we = 1;

              case (address)
                ADDR_CTRL:
                  begin
                    init     = write_data[CTRL_INIT_BIT];
                    next     = write_data[CTRL_NEXT_BIT];
                    finalize = write_data[CTRL_FINAL_BIT];
                  end

                ADDR_CONFIG:     config_we     = 1;
                ADDR_FINAL_SIZE: final_size_we = 1;

                default:
                  begin
                  end
              endcase // case (address)
            end // if (we)

          else
            begin
              case (address)
                ADDR_NAME0:      tmp_read_data = CORE_NAME0;
                ADDR_NAME1:      tmp_read_data = CORE_NAME1;
                ADDR_VERSION:    tmp_read_data = CORE_VERSION;
                ADDR_CTRL:       tmp_read_data = {31'h0, keylen_reg};
                ADDR_STATUS:     tmp_read_data = {30'h0, valid_reg, ready_reg};
                ADDR_FINAL_SIZE: tmp_read_data = {24'h0, final_size_reg};
                ADDR_RESULT0:    tmp_read_data = result_reg[127 : 96];
                ADDR_RESULT1:    tmp_read_data = result_reg[95 : 64];
                ADDR_RESULT2:    tmp_read_data = result_reg[63 : 32];
                ADDR_RESULT3:    tmp_read_data = result_reg[31 : 0];

                default:
                  begin
                  end
              endcase // case (address)
            end
        end
    end // addr_decoder


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


      // Handle result reg updates and clear
      if (reset_result_reg)
        begin
          result_new = 128'h0;
          result_we  = 1;
        end
      if (update_result_reg)
        begin
          result_new = core_result;
          result_we  = 1;
        end

      // Generation of subkey k1 and k2.
      k1_new = {core_result[126 : 0], 1'b0};
      if (core_result[127])
        k1_new = k1_new ^ R128;

      k2_new = {k1_new[126 : 0], 1'b0};
      if (k1_new[127])
        k2_new = k2_new ^ R128;


      // Padding of final block. We create a mask that preserves
      // the data in the block and zeroises all other bits.
      // We add a one to bit at the first non-data position.
      mask = 127'b0;
      if (final_size_reg[0])
        mask = {1'b1, mask[127 :  1]};

      if (final_size_reg[1])
        mask = {2'h3, mask[127 :  2]};

      if (final_size_reg[2])
        mask = {4'hf, mask[127 :  4]};

      if (final_size_reg[3])
        mask = {8'hff, mask[127 :  8]};

      if (final_size_reg[4])
        mask = {16'hffff, mask[127 :  16]};

      if (final_size_reg[5])
        mask = {32'hffffffff, mask[127 :  32]};

      if (final_size_reg[6])
        mask = {64'hffffffff_ffffffff, mask[127 :  64]};

      masked_block = {block_reg[0], block_reg[1], block_reg[2], block_reg[3]} & mask;
      padded_block = masked_block;
      padded_block[(127 - final_size_reg[6 : 0])] = 1'b1;


      // Tweak of final block. Based on if the final block is full or not.
      if (final_size_reg == AES_BLOCK_SIZE)
        tweaked_block = k1_reg ^ {block_reg[0], block_reg[1], block_reg[2], block_reg[3]};
      else
        tweaked_block = k2_reg ^ padded_block;


      // Input mux for the AES core.
      case (bmux_ctrl)
        BMUX_ZERO:
          core_block = 128'h0;

        BMUX_MESSAGE:
          core_block  = result_reg ^ {block_reg[0], block_reg[1],
                                      block_reg[2], block_reg[3]};

        BMUX_TWEAK:
          core_block  = result_reg ^ tweaked_block;
      endcase // case (bmux_ctrl)
    end


  //----------------------------------------------------------------
  // cmac_ctrl
  //
  // The FSM controlling the cmacm functionality.
  //----------------------------------------------------------------
  always @*
    begin : cmac_ctrl
      core_init         = 0;
      core_next         = 0;
      bmux_ctrl         = BMUX_ZERO;
      reset_result_reg  = 0;
      update_result_reg = 0;
      k1_k2_we          = 0;
      ready_new         = 0;
      ready_we          = 0;
      valid_new         = 0;
      valid_we          = 0;
      cmac_ctrl_new     = CTRL_IDLE;
      cmac_ctrl_we      = 0;

      case (cmac_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                ready_new        = 0;
                ready_we         = 1;
                valid_new        = 0;
                valid_we         = 1;
                core_init        = 1;
                reset_result_reg = 1;
                cmac_ctrl_new = CTRL_INIT_CORE;
                cmac_ctrl_we  = 1;
              end

            if (next)
              begin
                ready_new     = 0;
                ready_we      = 1;
                core_next     = 1;
                bmux_ctrl     = BMUX_MESSAGE;
                cmac_ctrl_new = CTRL_NEXT_BLOCK;
                cmac_ctrl_we  = 1;
              end

            if (finalize)
              begin
                ready_new     = 0;
                ready_we      = 1;
                bmux_ctrl     = BMUX_TWEAK;
                cmac_ctrl_new = CTRL_FINAL_BLOCK;
                cmac_ctrl_we  = 1;
              end
          end

        CTRL_INIT_CORE:
          begin
            if (core_ready)
              begin
                core_next     = 1;
                bmux_ctrl     = BMUX_ZERO;
                cmac_ctrl_new = CTRL_GEN_SUBKEYS;
                cmac_ctrl_we  = 1;
              end
          end

        CTRL_GEN_SUBKEYS:
          begin
            if (core_ready)
              begin
                ready_new     = 1;
                ready_we      = 1;
                k1_k2_we      = 1;
                cmac_ctrl_new = CTRL_IDLE;
                cmac_ctrl_we  = 1;
              end
          end

        CTRL_NEXT_BLOCK:
          begin
            if (core_ready)
              begin
                update_result_reg = 1;
                cmac_ctrl_new     = CTRL_IDLE;
                cmac_ctrl_we      = 1;
              end
          end

        CTRL_FINAL_BLOCK:
          begin
            if (core_ready)
              begin
                update_result_reg = 1;
                valid_new         = 1;
                valid_we          = 1;
                ready_new         = 1;
                ready_we          = 1;
                cmac_ctrl_new     = CTRL_IDLE;
                cmac_ctrl_we      = 1;
              end
          end

        default:
          begin
          end
      endcase // case (cmac_ctrl_reg)
    end

endmodule // cmac

//======================================================================
// EOF cmac.v
//======================================================================
