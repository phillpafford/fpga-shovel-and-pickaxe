//I am sorry, I am not lawyer and I do not know if I could license these modules under apache too.
//This is somehow derived work from alteras examples... maybe someone will help and tell me...
//If its needed, I am able to rewrite it, I have ready some different approaches to this problem.

//packed parameterized shift register --used in pipeline
//base of this structure comes from alteras examples
module parameterized_shift_packed (clk, in, out);
  parameter elementWidth = 32;
  parameter depth = 64;
  
	input clk;
	input [(elementWidth-1):0] in;
	output [(elementWidth-1):0] out;

	reg [(elementWidth-1):0] sr[0:(depth-1)];

	always@(posedge clk) begin
		sr[1:(depth-1)] <= sr[0:(depth-2)];
		sr[0] <= in;
	end
	
	assign out = sr[depth-1];

endmodule

//unpacked parameterized shift register --used in pipeline
//base of this structure comes from alteras examples
module parameterized_shift_unpacked (clk, in, out);
  parameter elementWidth = 32;
  parameter depth = 64;
	parameter elementCount = 8;
  
	input clk;
	input [(elementWidth-1):0] in[0:(elementCount-1)];
	output [(elementWidth-1):0] out[0:(elementCount-1)];

	reg [(elementWidth-1):0] sr[0:(depth-1)][0:(elementCount-1)];

	always@(posedge clk) begin
		sr[1:(depth-1)] <= sr[0:(depth-2)];
		sr[0] <= in;
	end
	
	assign out = sr[depth-1];

endmodule

module ram #(parameter elementWidth = 32,	parameter elementCount = 8, parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)],	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);
	reg [(elementWidth-1):0] ram[0:(depth-1)][0:(elementCount-1)];
	always @ (posedge clk) begin
		if (we)
			ram[write_addr] = data;
		q <= ram[read_addr];
	end
endmodule

function integer log2;
  input integer value;
  begin
    value = value-1;
    for (log2=0; value>0; log2=log2+1)
      value = value>>1;
  end
endfunction

module ram_packed #(parameter elementWidth = 32,	parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data,	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q);
	
	reg [(elementWidth-1):0] ram[0:(depth-1)];
	always @ (posedge clk) begin
		if (we)
			ram[write_addr] = data;
		q <= ram[read_addr];
	end
endmodule

//from some older tests
//module ram_slow #(parameter elementWidth = 32,	parameter elementCount = 8, parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)],	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);
//	reg [(elementWidth-1):0] ram[0:(depth-1)][0:(elementCount-1)];
//	always @ (posedge clk) begin
//		if (we)
//			ram[write_addr] <= data;
//		q <= ram[read_addr];
//	end
//endmodule
//
//function integer log2;
//  input integer value;
//  begin
//    value = value-1;
//    for (log2=0; value>0; log2=log2+1)
//      value = value>>1;
//  end
//endfunction
//
//module ram_packed_slow #(parameter elementWidth = 32,	parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data,	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q);
//	
//	reg [(elementWidth-1):0] ram[0:(depth-1)];
//	always @ (posedge clk) begin
//		if (we)
//			ram[write_addr] <= data;
//		q <= ram[read_addr];
//	end
//endmodule
