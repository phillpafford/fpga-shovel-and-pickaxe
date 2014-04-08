//Copyright 2014 Zeno Futurista (zenofuturista@gmail.com)
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

//I hope this writings will be usefull for someone, i am trying to follow nice variable namings
//so that it should be easy to understand even for people not skilled in verilog

//this module has following functions:
//deserializer/serializer for input output serial wire format
//sha job controller and result filter
//extern module queueram #(parameter elementWidth = 8,  parameter elementCount = 8) (input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)], input [7:0] write_addr,	input [7:0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);
extern module queueram #(parameter elementWidth = 32,	parameter elementCount = 8, parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)],	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);

module sha_core(
input clk,
//result from sha mix
input [7:0] hashResult[0:31],
//job which corresponds to result
input [31:0] jobIn,
//corresponding nonce
input [31:0] nonceIn,
//result available signal
input resultReady,
//input data available signal
input load,
//input data
input[7:0] in,
//transmitter ready signal
input read,

//output data for sha mix
output[7:0] dataToHash[0:79],
//job for mix
output [31:0] jobOut,
//output signal for mix to begin work
output reg startHashing,
//signal for transmitter - there is result available - start sending
output jobReady,
//output data for transmitter
output [7:0] out
);

//serializer/deserializer pointers
reg[10:0]  write_ptr;
reg[10:0]  read_ptr;

//output job nonce pair wires
wire [7:0] jobNonce[0:7];
wire [7:0] jobNonceMem[0:7];

//assemble job ID from deserialized data
assign jobOut = {header[84], header[85], header[86], header[87]};

//target used to compare result
wire [31:0] target = {header[80], header[81], header[82], header[83]};

//actual haeader working header (contains btc protocol header, target and jobID - header = 80B, target = 4B, job = 4B)
reg[7:0] header[0:87];

//data to be hashed (first 80B of receive header)
assign dataToHash = header[0:79];

//queue 8 zeros to be sent to client software when, (client should never use job ID 0)
assign jobNonce[0] = jobIn[31:24];
assign jobNonce[1] = jobIn[23:16];
assign jobNonce[2] = jobIn[15:8];
assign jobNonce[3] = jobIn[7:0];

assign jobNonce[4] = nonceIn[31:24];
assign jobNonce[5] = nonceIn[23:16];
assign jobNonce[6] = nonceIn[15:8];
assign jobNonce[7] = nonceIn[7:0];

//internal states
//we hit last nonce, signal that we need new work
reg requestWorkEnable;
//after all results have been sent, do actual request
wire requestNewWork = (requestWorkEnable & ~jobReady);
//we need to drop one result from result queue			 
reg resultSent;												

wire [7:0] zeros[0:7] = '{0,0,0,0,0,0,0,0};
//queues result if difficulty is met 
resultqueue rq(clk, difficultyMet | requestNewWork, resultSent, requestNewWork ? zeros : resultBuffer, jobNonceMem, jobReady);

//result buffer
reg [7:0] resultBuffer[0:7];
//difficulty met signal register
reg difficultyMet;

//some initials
initial  begin
	write_ptr = 0;
	read_ptr = 0;
	startHashing = 0;
end

//set actual output byte 
assign out = jobNonceMem[read_ptr];

always @(posedge clk) begin
	if(load) begin
		//there is something to deserialize
		header[write_ptr] <= in;
		if(write_ptr == 87) begin
			write_ptr <= 0;
			//all work data ready, start mixing
			startHashing <= 1;
		end else begin
			write_ptr <= write_ptr + 1;
		end
	end 

	//switch off startHashing signal after one cycle
	if(startHashing) begin
		startHashing <= 0;
	end
	
	//buffer input jobnonce
	resultBuffer <= jobNonce;
	if(resultReady) begin
		//job filter, decides if we met requested difficulty
		difficultyMet <= ({hashResult[31],hashResult[30],hashResult[29],hashResult[28]} == 0) & ({hashResult[27],hashResult[26],hashResult[25],hashResult[24]} <= target);
		
		//result with last nonce occured, we need new work
		if((nonceIn == 32'hffffffff) && (jobIn == jobOut)) begin
			requestWorkEnable <= 1;
		end
	end else begin
		//otherwise nothing happened
		difficultyMet <= 0;
	end
	
	//queue request new work packet (8 zeros)
	//client driver understands to this message and knows that it should schedule new work
	//therefore job should not use zero ID
	if(requestNewWork) begin
		requestWorkEnable <= 0;
	end
	
	//wait one cycle after sending last byte
	if(resultSent) begin
		resultSent <= 0;
	end
	
	//this end part is responsible for setting data to be sent
	//there must be some job waiting in queue, transmitter ready to read, and one cycle pause after previous result (queue drops, it is probably not neccessarry cause queue is passtrough)
	if(jobReady & read & ~resultSent) begin 
		if(read_ptr == 7) begin
			//end of packet
			read_ptr <= 0;
			resultSent <= 1;
		end else begin
			read_ptr <= read_ptr +1;
		end
	end
end

endmodule

//queue - same as in sha, but different data size
//inspiration taken from altera examples
//this queue now replaces last element if it is full, could be changed, but newer results are ussually better
//anyway it should be never filled, if so we need to change target
//specifically tailored for sha miner
module resultqueue(input clk, input write, input read, input [7:0] in[0:7], output [7:0] out[0:7], output available, output full);
	
	reg[7:0] write_addr, read_addr;
	reg[8:0] count;
	
	ram #(.elementWidth(8), .elementCount(8), .depth(256)) ram(clk, in, write_addr, (read & available) ? (read_addr+1) : read_addr, write, out);
	
	initial begin 
		read_addr = 0;
		write_addr = 0;
		count = 0;
	end
	
	//queue is full
	assign full = (count == 256);
	//some elements available
	assign available = (count > 0);
	
	always@(posedge clk) begin
		//put, drop and available case
		if(write & read & available) begin
			write_addr <= write_addr + 1;
			read_addr <= read_addr +1;
		//write only case
		end else if(write) begin
			write_addr <= write_addr + 1;
			//this causes rewrite of oldest value
			if(~full) begin
				count <= count +1;
			end
		//drop only case
		end else if(read & available) begin
			read_addr <= read_addr + 1;
			count <= count - 1;
		end 
	end
endmodule
