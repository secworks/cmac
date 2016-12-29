//======================================================================
//
// cmac_padding.v
// --------------
// Test logic to generate padding. The format of the padding is
// given in RFC 4493 and the NIST SP 800-38B specs. Basically
// pad the last block with the bits int the lat block followed
// by a one and as many zeros as needed to fill the final
// block. For a message of zero length, the block after padding
// is {1'b1, 127'b0}
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

module cmac_padding();

  //----------------------------------------------------------------
  // pad_block()
  //
  // pad a given block in with the given amount of data by
  // zeroisingt non-data bits and then adding a one to the first
  // bit after data.
  //----------------------------------------------------------------
  task pad_block(input [6 : 0] length, input [127 : 0] block_in,
                 output [127 : 0] block_out);
    begin : pad
      reg [127 : 0] mask;
      reg [127 : 0] masked_data;
      reg [127 : 0] padded_data;

      // Generate bitmask used to add zeros to part of block not being data.
      mask = 127'b0;
      if (length[0])
        mask = {1'b1, mask[127 :  1]};

      if (length[1])
        mask = {2'h3, mask[127 :  2]};

      if (length[2])
        mask = {4'hf, mask[127 :  4]};

      if (length[3])
        mask = {8'hff, mask[127 :  8]};

      if (length[4])
        mask = {16'hffff, mask[127 :  16]};

      if (length[5])
        mask = {32'hffffffff, mask[127 :  32]};

      if (length[6])
        mask = {64'hffffffff_ffffffff, mask[127 :  64]};

      masked_data = block_in & mask;
      padded_data = masked_data;
      padded_data[(127 - length)] = 1'b1;
      block_out = padded_data;


      $display("Length: %03d", length);
      $display("input_data:     0b%0128b", block_in);
      $display("Generated mask: 0b%0128b", mask);
      $display("Masked data:    0b%0128b", masked_data);
      $display("Padded data:    0b%0128b", padded_data);
      $display("");
    end
  endtask // pad_block


  //----------------------------------------------------------------
  // test_padding
  //----------------------------------------------------------------
  initial
    begin : test_padding
      reg [7 : 0]  length;
      reg [126 : 0] mask;

      reg [127 : 0] block_in;
      reg [127 : 0] block_out;

      block_in = 128'hdeadbeef_01020304_0a0b0c0d_55555555;

      $display("Testing cmac padding");
      $display("--------------------");
      $display("Block before padding: 0b%0128b", block_in);
      for (length = 0 ; length < 128 ; length = length + 1)
        begin
          pad_block(length, block_in, block_out);
        end
    end // test_padding

endmodule // cmac_padding

//======================================================================
// EOF cmac_padding.v
//======================================================================
