//======================================================================
//
// cmac.v
// ------
// CMAC based on AES.
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
  localparam CTRL_ENCDEC_BIT  = 0;
  localparam CTRL_KEYLEN_BIT  = 1;

  localparam ADDR_STATUS      = 8'h0a;
  localparam STATUS_READY_BIT = 0;
  localparam STATUS_VALID_BIT = 1;

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
  localparam BMUX_XOR_MESSAGE = 2;
  localparam BMUX_XOR_TWEAK   = 3;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg init_new;

  reg next_reg;
  reg next_new;

  reg final_reg;
  reg final_new;

  reg encdec_reg;
  reg keylen_reg;
  reg config_we;

  reg [31 : 0] block_reg [0 : 3];
  reg          block_we;

  reg [31 : 0] key_reg [0 : 7];
  reg          key_we;

  reg [127 : 0] result_reg;
  reg           valid_reg;
  reg           ready_reg;

  reg [2 : 0] cmac_ctrl_reg;
  reg [2 : 0] cmac_ctrl_new;
  reg         cmac_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;

  wire           core_encdec;
  wire           core_init;
  wire           core_next;
  wire           core_ready;
  wire [255 : 0] core_key;
  wire           core_keylen;
  reg  [127 : 0] core_block;
  wire [127 : 0] core_result;
  wire           core_valid;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign read_data = tmp_read_data;

  assign core_key = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                     key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_init   = init_reg;
  assign core_next   = next_reg;
  assign core_encdec = encdec_reg;
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
          for (i = 0 ; i < 4 ; i = i + 1)
            block_reg[i] <= 32'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            key_reg[i] <= 32'h0;

          init_reg   <= 0;
          next_reg   <= 0;
          encdec_reg <= 0;
          keylen_reg <= 0;

          result_reg <= 128'h0;
          valid_reg  <= 0;
          ready_reg  <= 0;
        end
      else
        begin
          ready_reg  <= core_ready;
          valid_reg  <= core_valid;
          result_reg <= core_result;
          init_reg   <= init_new;
          next_reg   <= next_new;

          if (config_we)
            begin
              encdec_reg <= write_data[CTRL_ENCDEC_BIT];
              keylen_reg <= write_data[CTRL_KEYLEN_BIT];
            end

          if (key_we)
            key_reg[address[2 : 0]] <= write_data;

          if (block_we)
            block_reg[address[1 : 0]] <= write_data;
        end
    end // reg_update


  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  always @*
    begin : api
      init_new      = 0;
      next_new      = 0;
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

              if ((address >= ADDR_BLOCK0) && (address <= ADDR_BLOCK7))
                key_we = 1;

              case (address)
                ADDR_CTRL:
                  begin
                    init_new = write_data[CTRL_INIT_BIT];
                    next_new = write_data[CTRL_NEXT_BIT];
                    final_new = write_data[CTRL_FINAL_BIT];
                  end

                ADDR_CONFIG: config_we = 1;

                default:
                  begin
                  end
              endcase // case (address)
            end // if (we)

          else
            begin
              case (address)
                ADDR_NAME0:   tmp_read_data = CORE_NAME0;
                ADDR_NAME1:   tmp_read_data = CORE_NAME1;
                ADDR_VERSION: tmp_read_data = CORE_VERSION;
                ADDR_CTRL:    tmp_read_data = {28'h0, keylen_reg, encdec_reg, next_reg, init_reg};
                ADDR_STATUS:  tmp_read_data = {30'h0, valid_reg, ready_reg};
                ADDR_RESULT0: tmp_read_data = result_reg[127 : 96];
                ADDR_RESULT1: tmp_read_data = result_reg[95 : 64];
                ADDR_RESULT2: tmp_read_data = result_reg[63 : 32];
                ADDR_RESULT3: tmp_read_data = result_reg[31 : 0];

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
  // to the AES core and som xor gates for the logic.
  //----------------------------------------------------------------
  always @*
    begin : cmac_datapath
      reg [127 : 0] tweak;

      case (bmux_ctrl)
        BMUX_ZERO:
          core_block = 128'h0;

        BMUX_MESSAGE:
          core_block  = {block_reg[0], block_reg[1],
                         block_reg[2], block_reg[3]};

        BMUX_XOR_MESSAGE:
          core_block  = result_reg ^ {block_reg[0], block_reg[1],
                                      block_reg[2], block_reg[3]};

        BMUX_XOR_TWEAK:
          core_block  = result_reg ^ tweak;
      endcase // case (bmux_ctrl)
    end


  //----------------------------------------------------------------
  // cmac_ctrl
  //
  // The FSM controlling the cmacm functionality.
  //----------------------------------------------------------------
  always @*
    begin : cmac_ctrl

    end

endmodule // cmac

//======================================================================
// EOF cmac.v
//======================================================================
