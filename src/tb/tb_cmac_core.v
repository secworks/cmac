//======================================================================
//
// tb_cmac_core.v
// --------------
// Testbench for CMAC core based on AES.
// Testvectors from:
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CMAC.pdf
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

module tb_cmac_core();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam DEBUG = 1;

  localparam CLK_HALF_PERIOD = 1;
  localparam CLK_PERIOD      = 2 * CLK_HALF_PERIOD;


  // The DUT address map.
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

  localparam ADDR_FINAL_SIZE  = 8'h0b;

  localparam ADDR_KEY0        = 8'h10;
  localparam ADDR_KEY1        = 8'h11;
  localparam ADDR_KEY2        = 8'h12;
  localparam ADDR_KEY3        = 8'h13;
  localparam ADDR_KEY4        = 8'h14;
  localparam ADDR_KEY5        = 8'h15;
  localparam ADDR_KEY6        = 8'h16;
  localparam ADDR_KEY7        = 8'h17;

  localparam ADDR_BLOCK0      = 8'h20;
  localparam ADDR_BLOCK1      = 8'h21;
  localparam ADDR_BLOCK2      = 8'h22;
  localparam ADDR_BLOCK3      = 8'h23;

  localparam ADDR_RESULT0     = 8'h30;
  localparam ADDR_RESULT1     = 8'h31;
  localparam ADDR_RESULT2     = 8'h32;
  localparam ADDR_RESULT3     = 8'h33;


  localparam AES_128_BIT_KEY = 0;
  localparam AES_256_BIT_KEY = 1;

  localparam AES_DECIPHER = 1'b0;
  localparam AES_ENCIPHER = 1'b1;


  localparam AES_BLOCK_SIZE = 128;


  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0]  cycle_ctr;
  reg [31 : 0]  error_ctr;
  reg [31 : 0]  tc_ctr;
  reg           tc_correct;
  reg           debug_ctrl;

  reg [31 : 0]  read_data;
  reg [127 : 0] result_data;

  reg            tb_clk;
  reg            tb_reset_n;
  reg [255 : 0]  tb_key;
  reg            tb_keylen;
  reg [7 : 0]    tb_final_size;
  reg            tb_init;
  reg            tb_next;
  reg            tb_finalize;
  reg [127 : 0]  tb_block;
  wire [127 : 0] tb_result;
  wire           tb_ready;
  wire           tb_valid;


  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  cmac_core dut(
           .clk(tb_clk),
           .reset_n(tb_reset_n),

           .key(tb_key),
           .keylen(tb_keylen),
           .final_size(tb_final_size),
           .init(tb_init),
           .next(tb_next),
           .finalize(tb_finalize),
           .block(tb_block),
           .result(tb_result),
           .ready(tb_ready),
           .valid(tb_valid)
          );


  //----------------------------------------------------------------
  // Concurrent assignments.
  //----------------------------------------------------------------


  //----------------------------------------------------------------
  // clk_gen
  //
  // Always running clock generator process.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end // clk_gen


  //----------------------------------------------------------------
  // sys_monitor()
  //
  // An always running process that creates a cycle counter and
  // conditionally displays information about the DUT.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      cycle_ctr = cycle_ctr + 1;

      #(CLK_PERIOD);

      if (debug_ctrl)
        begin
          dump_dut_state();
        end
    end


  //----------------------------------------------------------------
  // dump_dut_state()
  //
  // Dump the state of the dump when needed.
  //----------------------------------------------------------------
  task dump_dut_state;
    begin
      $display("cycle:  0x%016x", cycle_ctr);
      $display("Inputs and outputs:");
      $display("init = 0x%01x, next = 0x%01x, finalize = 0x%01x",
               dut.init, dut.next, dut.finalize);
      $display("config: keylength = 0x%01x, final_size = 0x%01x",
               dut.keylen, dut.final_size);
      $display("block = 0x%032x, ready = 0x%01x, result =  0x%032x",
               dut.block, dut.ready, dut.result);

      $display("Internal states:");
      $display("k1 = 0x%016x, k2 = 0x%016x", dut.k1_reg, dut.k2_reg);
      $display("ready = 0x%01x, valid = 0x%01x, result_we = 0x%01x, block_mux = 0x%02x, ctrl_state = 0x%02x",
               dut.ready, dut.valid, dut.result_we, dut.bmux_ctrl, dut.cmac_ctrl_reg);
      $display("tweaked_block: 0x%032x", dut.cmac_datapath.tweaked_block);
      $display("");
    end
  endtask // dump_dut_state


  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("TB: Resetting dut.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // display_test_results()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_results;
    begin
      $display("");
      if (error_ctr == 0)
        begin
          $display("%02d test completed. All test cases completed successfully.", tc_ctr);
        end
      else
        begin
          $display("%02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
        end
    end
  endtask // display_test_results


  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr     = 0;
      error_ctr     = 0;
      tc_ctr        = 0;
      debug_ctrl    = 0;

      tb_clk        = 1'h0;
      tb_reset_n    = 1'h1;
      tb_key        = 256'h0;
      tb_keylen     = 1'h0;
      tb_final_size = 8'h0;
      tb_init       = 1'h0;
      tb_next       = 1'h0;
      tb_finalize   = 1'h0;
      tb_block      = 128'h0;
    end
  endtask // init_sim


  //----------------------------------------------------------------
  // inc_tc_ctr
  //----------------------------------------------------------------
  task inc_tc_ctr;
    tc_ctr = tc_ctr + 1;
  endtask // inc_tc_ctr


  //----------------------------------------------------------------
  // inc_error_ctr
  //----------------------------------------------------------------
  task inc_error_ctr;
    error_ctr = error_ctr + 1;
  endtask // inc_error_ctr


  //----------------------------------------------------------------
  // pause_finish()
  //
  // Pause for a given number of cycles and then finish sim.
  //----------------------------------------------------------------
  task pause_finish(input [31 : 0] num_cycles);
    begin
      $display("Pausing for %04d cycles and then finishing hard.", num_cycles);
      #(num_cycles * CLK_PERIOD);
      $finish;
    end
  endtask // pause_finish


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag to be set in dut.
  //----------------------------------------------------------------
  task wait_ready;
    begin : wready
      while (tb_ready == 0)
        #(CLK_PERIOD);
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // tc1_reset_state
  //
  // Check that registers in the dut are being correctly reset.
  //----------------------------------------------------------------
  task tc1_reset_state;
    begin : tc1
      inc_tc_ctr();
      debug_ctrl = 1;
      $display("TC1: Check that the dut registers are correctly reset.");
      #(2 * CLK_PERIOD);
      reset_dut();
      #(2 * CLK_PERIOD);
    end
  endtask // tc1_reset_state


  //----------------------------------------------------------------
  // tc2_gen_subkeys
  //
  // Check that subkeys k1 and k2 are correctly generated.
  // The keys and test vectors are from NIST SP 800-38B, D.1.
  //----------------------------------------------------------------
  task tc2_gen_subkeys;
    begin : tc2
      inc_tc_ctr();
      tc_correct = 1;

      debug_ctrl = 1;

      $display("TC2: Check that k1 and k2 subkeys are correctly generated.");
      tb_key    = 256'h2b7e1516_28aed2a6_abf71588_09cf4f3c_00000000_00000000_00000000_00000000;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      if (dut.k1_reg != 128'hfbeed618_35713366_7c85e08f_7236a8de)
        begin
          $display("TC2: ERROR - K1 incorrect. Expected 0xfbeed618_35713366_7c85e08f_7236a8de, got 0x%032x.", dut.k1_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (dut.k2_reg != 128'hf7ddac30_6ae266cc_f90bc11e_e46d513b)
        begin
          $display("TC2: ERROR - K2 incorrect. Expected 0x7ddac30_6ae266cc_f90bc11e_e46d513b, got 0x%032x.", dut.k2_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC2: SUCCESS - K1 and K2 subkeys correctly generated.");
      else
        $display("TC2: NO SUCCESS - Subkeys not correctly generated.");
      $display("");
    end
  endtask // tc2


  //----------------------------------------------------------------
  // tc3_empty_message
  //
  // Check that the correct ICV is generated for an empty message.
  // The keys and test vectors are from the NIST spec, RFC 4493.
  //----------------------------------------------------------------
  task tc3_empty_message;
    begin : tc3
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC3: Check that correct ICV is generated for an empty message.");

      tb_key    = 256'h2b7e1516_28aed2a6_abf71588_09cf4f3c_00000000_00000000_00000000_00000000;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();

      $display("TC3: cmac_core initialized. Now for the final, empty message block.");
      tb_final_size = 8'h0;
      tb_finalize = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      $display("TC3: cmac_core finished.");
      if (tb_result != 128'hbb1d6929e95937287fa37d129b756746)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC3: Error - Expected 0xbb1d6929e95937287fa37d129b756746, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC3: SUCCESS - ICV for empty message correctly generated.");
      else
        $display("TC3: NO SUCCESS - ICV for empty message not correctly generated.");
      $display("");
    end
  endtask // tc3


  //----------------------------------------------------------------
  // tc4_single_block_message
  //
  // Check that the correct ICV is generated for a single block
  // message.  The keys and test vectors are from the NIST spec,
  // RFC 4493.
  //----------------------------------------------------------------
  task tc4_single_block_message;
    begin : tc4
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC4: Check that correct ICV is generated for a single block message.");

      tb_key    = 256'h2b7e1516_28aed2a6_abf71588_09cf4f3c_00000000_00000000_00000000_00000000;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();

      $display("TC4: cmac_core initialized. Now for the final, full message block.");

      tb_block      = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
      tb_final_size = AES_BLOCK_SIZE;
      tb_finalize   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      $display("TC4: cmac_core finished.");
      if (tb_result != 128'h070a16b4_6b4d4144_f79bdd9d_d04a287c)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC4: Error - Expected 0x070a16b4_6b4d4144_f79bdd9d_d04a287c, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC4: SUCCESS - ICV for single block message correctly generated.");
      else
        $display("TC4: NO SUCCESS - ICV for single block message not correctly generated.");
      $display("");
    end
  endtask // tc4


  //----------------------------------------------------------------
  // tc5_two_and_a_half_block_message
  //
  // Check that the correct ICV is generated for a message that
  // consists of two and a half (40 bytes) blocks.
  // The keys and test vectors are from the NIST spec, RFC 4493.
  //----------------------------------------------------------------
  task tc5_two_and_a_half_block_message;
    begin : tc5
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC5: Check that correct ICV is generated for a two and a half block message.");
      tb_key    = 256'h2b7e1516_28aed2a6_abf71588_09cf4f3c_00000000_00000000_00000000_00000000;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();
      $display("TC5: cmac_core initialized. Now we process two full blocks.");

      tb_block = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();
      $display("TC5: First block done.");

      tb_block = 128'hae2d8a57_1e03ac9c_9eb76fac_45af8e51;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();
      $display("TC5: Second block done.");

      $display("TC5: Now we process the final half block.");
      tb_block      = 128'h30c81c46_a35ce411_00000000_00000000;
      tb_final_size = 8'h40;
      tb_finalize = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();
      #(2 * CLK_PERIOD);
      debug_ctrl = 0;
      $display("TC5: cmac_core finished.");

      if (tb_result != 128'hdfa66747_de9ae630_30ca3261_1497c827)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC5: Error - Expected 0xdfa66747_de9ae630_30ca3261_1497c827, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC5: SUCCESS - ICV for two and a half block message correctly generated.");
      else
        $display("TC5: NO SUCCESS - ICV for two and a half block message not correctly generated.");
      $display("");
    end
  endtask // tc5


  //----------------------------------------------------------------
  // tc6_four_block_message
  //
  // Check that the correct ICV is generated for a message that
  // consists of four complete (64 bytes) blocks.
  // The keys and test vectors are from the NIST spec, RFC 4493.
  //----------------------------------------------------------------
  task tc6_four_block_message;
    begin : tc6
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC6: Check that correct ICV is generated for a four block message.");
      tb_key    = 256'h2b7e1516_28aed2a6_abf71588_09cf4f3c_00000000_00000000_00000000_00000000;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();
      $display("TC6: cmac_core initialized. Now we process four full blocks.");

      tb_block = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block = 128'hae2d8a57_1e03ac9c_9eb76fac_45af8e51;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block = 128'h30c81c46_a35ce411_e5fbc119_1a0a52ef;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block      = 128'hf69f2445_df4f9b17_ad2b417b_e66c3710;
      tb_final_size = AES_BLOCK_SIZE;
      tb_finalize   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();
      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      if (tb_result != 128'h51f0bebf_7e3b9d92_fc497417_79363cfe)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC6: Error - Expected 0x51f0bebf_7e3b9d92_fc497417_79363cfe, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC6: SUCCESS - ICV for four block message correctly generated.");
      else
        $display("TC6: NO SUCCESS - ICV for four block message not correctly generated.");
      $display("");
    end
  endtask // tc6


  //----------------------------------------------------------------
  // tc7_key256_four_block_message
  //
  // Check that the correct ICV is generated for a message that
  // consists of four complete (64 bytes) blocks. In this test
  // the the key is 256 bits.
  // The keys and test vectors are from the NIST spec.
  //----------------------------------------------------------------
  task tc7_key256_four_block_message;
    begin : tc7
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC7: Check that correct ICV is generated for a four block message usint a 256 bit key.");
      tb_key    = 256'h603deb10_15ca71be_2b73aef0_857d7781_1f352c07_3b6108d7_2d9810a3_0914dff4;
      tb_keylen = 1'h1;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();
      $display("TC7: cmac_core initialized. Now we process four full blocks.");

      tb_block = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block = 128'hae2d8a57_1e03ac9c_9eb76fac_45af8e51;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block = 128'h30c81c46_a35ce411_e5fbc119_1a0a52ef;
      tb_next  = 1'h1;
      #(2 * CLK_PERIOD);
      tb_next  = 1'h0;
      wait_ready();

      tb_block = 128'hf69f2445_df4f9b17_ad2b417b_e66c3710;
      tb_final_size = AES_BLOCK_SIZE;
      tb_finalize   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();
      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      if (tb_result != 128'he1992190_549f6ed5_696a2c05_6c315410)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC7: Error - Expected 0xe1992190_549f6ed5_696a2c05_6c315410, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC7: SUCCESS - ICV for four block message using 256 bit key correctly generated.");
      else
        $display("TC7: NO SUCCESS - ICV for four block message using 256 bit key not correctly generated.");
      $display("");
    end
  endtask // tc7


  //----------------------------------------------------------------
  // tc8_single_block_all_zero_message
  //
  // Check that we can get the correct ICV when using the test
  // vector key from RFC5297 and a single block all zero message.
  //----------------------------------------------------------------
  task tc8_single_block_all_zero_message;
    begin : tc8_single_block_all_zero_message
      integer i;

      inc_tc_ctr();
      tc_correct = 1;
      debug_ctrl = 1;

      $display("TC8: Check that correct ICV is generated for a single block, all zero message.");

      tb_key    = 256'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0_f0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff;
      tb_keylen = 1'h0;
      tb_init   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_init   = 1'h0;
      wait_ready();

      $display("TC4: cmac_core initialized. Now for the final, full message block.");

      tb_block      = 128'h0;
      tb_final_size = AES_BLOCK_SIZE;
      tb_finalize   = 1'h1;
      #(2 * CLK_PERIOD);
      tb_finalize = 1'h0;
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_ctrl = 0;

      $display("TC8: cmac_core finished.");
      if (tb_result != 128'h0e04dfaf_c1efbf04_01405828_59bf073a)
        begin
          tc_correct = 0;
          inc_error_ctr();
          $display("TC8: Error - Expected 0x0e04dfaf_c1efbf04_01405828_59bf073a, got 0x%032x",
                   tb_result);
        end

      if (tc_correct)
        $display("TC8: SUCCESS - ICV for single block message correctly generated.");
      else
        $display("TC8: NO SUCCESS - ICV for single block message not correctly generated.");
      $display("");
    end
  endtask // tc8_single_block_all_zero_message


  //----------------------------------------------------------------
  // main
  //
  // The main test functionality.
  //----------------------------------------------------------------
  initial
    begin : main
      $display("*** Testbench for CMAC_CORE started ***");
      $display("");

      init_sim();

      tc1_reset_state();
      tc2_gen_subkeys();
      tc3_empty_message();
      tc4_single_block_message();
      tc5_two_and_a_half_block_message();
      tc6_four_block_message();
      tc7_key256_four_block_message();
      tc8_single_block_all_zero_message();

      display_test_results();

      $display("*** CMAC_CORE simulation done. ***");
      $finish;
    end // main

endmodule // tb_cmac_core

//======================================================================
// EOF tb_cmac_core.v
//======================================================================
