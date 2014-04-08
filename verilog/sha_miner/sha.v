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

//I hope you will like it :)
//Well, I like alteras quartus and its compiler, good piece of work!

module sha256(input clk, input [7:0] in[0:79], input [31:0] job, input doWork, output reg[7:0] resultOut[0:31], output reg[31:0] resultJobOut, output reg[31:0] resultNonceOut, output reg resultAvailable);
	//unroll parameter
	parameter unroll = 4;

	//sha initial digest constant
	wire [31:0] H [0:7];
	//initial digest (sha state)
	assign H = '{32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};

	//actual work registers
	reg[7:0] workBuffer[0:79];
	reg[31:0] currentJob;
	reg midstateReady;
	reg[31:0] midstate[0:7];
	
	//signals that there is task to be scheduled
	reg scheduleTask;
	
	//interconnection wires and regs for first pipeline follow
	//task state wire and reg
	reg[31:0] stateOut;
	wire[31:0] stateIn;

	//digest wires and registers
	reg[31:0] digestOut[0:7];
	reg[31:0] digestOutOriginal[0:7];
	wire [31:0] digestIn [0:7];
	wire [31:0] digestInOriginal [0:7];
	
	//wires for first phase midstate computation
	//second part with 12 header bytes + nonce and padding
	wire[7:0] firstStageSecondPart[0:63];
	wire[7:0] dataIn[0:63];
	
	//used for words
	reg[31:0] wordsOut[0:15];
	wire[31:0] wordsIn[0:15];
	
	//nonce vars
	reg[31:0] nonceOut;
	wire[31:0] nonceIn;
	
	//job vars
	reg[31:0] jobOut;
	wire[31:0] jobIn;
	
	//pipeline for first part of computation
	sha_pipeline #(unroll) shap(clk,  stateOut, digestOut, digestOutOriginal, wordsOut, jobOut, nonceOut, digestIn, digestInOriginal, wordsIn, stateIn, jobIn, nonceIn);
	
	//wires and regs for internal connection with second pipeline
	reg[31:0] stateOutb;
	wire[31:0] stateInb;
	
	reg[31:0] nonceOutb;
	wire[31:0] nonceInb;
	
	reg[31:0] digestOutb[0:7];
	wire [31:0] digestInb [0:7];
	
	reg[31:0] digestOutOriginalb[0:7];
	wire [31:0] digestInOriginalb [0:7];
	
	reg[31:0] wordsOutb[0:15];
	wire[31:0] wordsInb[0:15];

	reg[31:0] jobOutb;
	wire[31:0] jobInb;

	//pipeline for second part of computation
	sha_pipeline #(unroll) shapb(clk,  stateOutb, digestOutb, digestOutOriginalb, wordsOutb, jobOutb, nonceOutb, digestInb, digestInOriginalb, wordsInb, stateInb, jobInb, nonceInb);
	
	//put second part of input data to queue, used only at several initial cycles after job submition (midstate is not known)
	shaqueue #(.elementWidth(8), .elementCount(64), .depth(1 + unroll)) fsspq(clk, (firstPipelineReady & scheduleTask & ~midstateReady), midstateStageReady, firstStageSecondPart, dataIn);
	
	//inputs for each stage
	wire[7:0] stageTwoPadding[0:31];
	
	//combinationals needed to assemble new data to hash (paddings, nonces...)
	reg[31:0] newNonce;
	wire [31:0] newDigest[0:7];
	always @(*) begin
		for(int i =0; i < 8; i++) begin
			newDigest[i] = (digestIn[i] + digestInOriginal[i]);	
		end
		
		//this is maybe not the best way to set this up, but i find it readable and easy to understand
		firstStageSecondPart[0:11] = workBuffer[64:75];
		//assembly nonce for new sha hashing
		firstStageSecondPart[15] = newNonce;
		firstStageSecondPart[14] = (newNonce >> 8);
		firstStageSecondPart[13] = (newNonce >> 16);
		firstStageSecondPart[12] = (newNonce >> 24);
		
		//padding to 128 bytes of 80B input (first stage second sha part)
		firstStageSecondPart[16] = 128;
		for(int i =1; i < 46; i++) begin
			firstStageSecondPart[16+i] = 0;
		end
		firstStageSecondPart[62] = 2;
		firstStageSecondPart[63] = 128;
		
		//padding for second stage input
		stageTwoPadding[0] = 128;
		for(int i =1; i < 30; i++) begin
			stageTwoPadding[i] = 0;
		end
		stageTwoPadding[30] = 1;
		stageTwoPadding[31] = 0;
	end
	
	//some states to be easilly readable
	wire firstPipelineWorkIn = stateIn[31];
	wire firstStageReady = (stateIn[7:0] == 128);
	wire firstPipelineReady = ~firstPipelineWorkIn | firstStageReady;
	wire firstPipelineResultReady = firstPipelineWorkIn & firstStageReady;
	
	wire secondPipelineWorkIn = stateInb[31];
	wire secondPipelineResultReady = secondPipelineWorkIn & (stateInb[7:0] == 64);
	wire secondPipelineReady = (~secondPipelineWorkIn | secondPipelineResultReady);
	
	wire midstateStageReady = (stateIn[7:0] == 64);
	
	always@(posedge clk) begin
		if(doWork) begin
			//set new data
			workBuffer <= in;
			//set new job
			currentJob <= job;
			//reset nonce 
			//concatenation of input bytes in header
			newNonce <= {in[76],in[77],in[78],in[79]};
			
			//TODO reset queue... seems like it is not needed - jobstate guarantees drops (must test)
			midstateReady <= 0;
			scheduleTask <= 1;
		end
	
		if(firstPipelineReady) begin
			if(scheduleTask) begin
				//now we can schedule task, there is something to do! :) as always in life!
				if(~midstateReady) begin
					//begining of new work - there is no midstate known
					//midstate is the same result of first 64 bytes part sha transform (because of nonce, which changes, lies at bytes 76-79 [zero index])
					//--> concatenation
					for(int i =0; i<16; i++) begin
						wordsOut[i] <= (workBuffer[4*i] <<< 24) | (workBuffer[4*i + 1] <<< 16) | (workBuffer[4*i + 2] <<< 8) | (workBuffer[4*i + 3]); 
					end
					//set state variables					
					stateOut[31] <= 1;
					stateOut[7:0] <= 0;
					
					//set up other job infos
					jobOut <= currentJob;
					nonceOut <= newNonce;
					//increment nonce
					newNonce <= newNonce + 1;
					
					//we hit end of nonce interval - stop scheduling
					if(newNonce == (32'hffffffff)) begin
						scheduleTask <= 0;
					end
					
					//set initial digest
					digestOut <= H;
					digestOutOriginal <= H;
				end else begin
					//new work scheduling is in stage, where midstate is known (first sha done)
					stateOut[31] <= 1;
					
					//set digest from midstate
					digestOut <= midstate;
					digestOutOriginal <= midstate;
					//set job info
					jobOut <= currentJob;
					nonceOut <= newNonce;
					
					//use data out assembly, that generates new second part of first sha (few bytes from header with changing nonce + padding)
					//this is in fact some kind of concatenation
					for(int i =0; i<16; i++) begin
						wordsOut[i] <= (firstStageSecondPart[4*i] <<< 24) | (firstStageSecondPart[4*i + 1] <<< 16) | (firstStageSecondPart[4*i + 2] <<< 8) | (firstStageSecondPart[4*i + 3]); 
					end
					
					//increment nonce
					newNonce <= newNonce + 1;
					
					//if we hit end of nonce interval - stop scheduling
					if(newNonce == (32'hffffffff)) begin
						scheduleTask <= 0;
					end
					//we continue from state 64 (midstate known)
					stateOut[7:0] <= 64;
				end
			end else begin
				//otherwise fill pipeline with zeros 
				stateOut <= 0;
				jobOut <= 0;
				nonceOut <= 0;
				for(int i = 0; i < 16; i++) begin
					wordsOut[i] <= 0;
				end
				
				for(int i = 0; i < 8; i++) begin
					digestOut[i] <= 0;
					digestOutOriginal[i] <= 0;
				end
			end
		end
		
		if(firstPipelineWorkIn) begin
			//this state is possible only at the beginning, when there is no midstate...
			if(midstateStageReady) begin
				//second part of data mix stored in queue
				//concatenate/assemble words variable
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (dataIn[4*i] <<< 24) | (dataIn[4*i + 1] <<< 16) | (dataIn[4*i + 2] <<< 8) | (dataIn[4*i + 3]); 
				end
					
				//complete digest - add original state/digest (H) to new one and set midstate.
				digestOut <= newDigest;	
				midstate <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//continue with second part (from midstate), set job etc.
				stateOut <= stateIn;
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				//mark midstate ready for this job
				midstateReady <= 1;
			end else if(firstStageReady) begin
				//first sha is complete, use its final digest and info as input for second sha pipeline
				digestOutb <= H;
				digestOutOriginalb <= H;
				jobOutb <= jobIn;
				nonceOutb <= nonceIn;
				
				//set up initial words.
				//concatenate some stages
				for(int i =0; i < 8; i++) begin
					wordsOutb[i] <= newDigest[i];	
					wordsOutb[8+i] <= (stageTwoPadding[4*i] <<< 24) | (stageTwoPadding[4*i + 1] <<< 16) | (stageTwoPadding[4*i + 2] <<< 8) | (stageTwoPadding[4*i + 3]); 	
				end
				//set state variables
				stateOutb[7:0] <= 0;
				stateOutb[31] <= 1;
			end else begin
				//some middle phase, continue mixing
				wordsOut <= wordsIn;
				digestOut <= digestIn;
				digestOutOriginal <= digestInOriginal;
				stateOut <= stateIn;
				jobOut <= jobIn;
				nonceOut <= nonceIn;
			end
		end
		
		//controls when to clean/discard data in second pipeline
		//second pipe is ready and first one has nothing to schedule...
		if(secondPipelineReady & ~firstPipelineResultReady) begin
			stateOutb <= 0;
			nonceOutb <= 0;
			for(int i = 0; i < 16; i++) begin
				wordsOutb[i] <= 0;
			end
			
			for(int i = 0; i < 8; i++) begin
				digestOutb[i] <= 0;
				digestOutOriginalb[i] <= 0;
			end
			jobOutb <= 0;
		end

		//if there is some result from second pipeline, process it
		if(secondPipelineResultReady) begin
			//end part of computation - we can signal completed work
			//deconcatenate digest to bytes
			for(int i =0; i < 8; i++) begin
				resultOut[i*4 + 3] <= (digestInb[i] + digestInOriginalb[i]);
				resultOut[i*4 + 2] <= (digestInb[i] + digestInOriginalb[i]) >>> 8;
				resultOut[i*4 + 1] <= (digestInb[i] + digestInOriginalb[i]) >>> 16;
				resultOut[i*4] <= (digestInb[i] + digestInOriginalb[i]) >>> 24;	
			end
			resultJobOut <= jobInb;
			resultNonceOut <= nonceInb;
			resultAvailable <= 1;
		end else if(secondPipelineWorkIn) begin 
			//otherwise continue in computation
			wordsOutb <= wordsInb;
			nonceOutb <= nonceInb;
			jobOutb <= jobInb;
			digestOutb <= digestInb;
			digestOutOriginalb <= digestInOriginalb;
			stateOutb <= stateInb;
			resultAvailable <= 0;
		end else begin
			//realy, there is no result yet :)
			resultAvailable <= 0;
		end		
	end
	
endmodule

extern module parameterized_shift_unpacked #(parameter elementWidth = 8, parameter depth = 8,	parameter elementCount = 64) (input clk, input [(elementWidth-1):0] in[0:(elementCount-1)], output [(elementWidth-1):0] out[0:(elementCount-1)]);

//I believe it is readable and easy to understand
module sha_pipeline(input clk,  input [31:0] stateIn, input[31:0] digestIn[0:7], input[31:0] digestInOriginal[0:7], input [31:0] wordsIn[0:15], input [31:0] jobIn, input [31:0] nonceIn, output [31:0] digestOutNew[0:7], output [31:0] digestOutOriginal[0:7], output [31:0] wordsOut[0:15], output [31:0] stateOut, output  [31:0] jobOut, output  [31:0] nonceOut);
	
	//valid values are 64,32,16,8,4,2,1
	parameter N = 64;
	
	//unroll assertion (taken from serial interface example)
	generate
		if(~(N==64 | N==32 | N==16 | N ==8 | N ==4 | N ==2 | N==1)) ASSERTION_ERROR PARAMETER_OUT_OF_RANGE("SHA unroll parameter is not valid!");
	endgenerate
	
	//some interconnects
	wire [31:0] stateMid;
	wire [15:0] stateMidm;
	
	//we need to shift some values in parallel with actual computation (usually needed in next steps)
	parameterized_shift_packed #(.elementWidth(32), .depth(N)) db(clk, stateIn, stateMid);
	parameterized_shift_packed #(.elementWidth(32), .depth(N)) db1(clk, jobIn, jobOut);
	parameterized_shift_packed #(.elementWidth(32), .depth(N)) db2(clk, nonceIn, nonceOut);
	parameterized_shift_unpacked #(.elementWidth(32), .elementCount(8),.depth(N)) db3(clk, digestInOriginal, digestOutOriginal);
	
	//sha unrolled according to the N parameter
	sha_mix #(N) mix(clk, stateIn[15:0], wordsIn, digestIn, digestOutNew, wordsOut, stateMidm);
	
	//apply new index to state if needed (ie. there was valid task in pipeline)
	assign stateOut = {stateMid[31:6], stateMid[31] ? stateMidm : 16'h0};
	
endmodule

//work work work, mix mix mix
module sha_mix(input clk,input[15:0] indexIn, input [31:0] wordsIn[0:15], input [31:0] digestIn[0:7], output [31:0] digestOut[0:7],output [31:0] wordsOut[0:15], output[15:0] indexOut);
		wire [31:0] K[0:63];
		//unroll parameter
		parameter N = 4;
		
		//sha constant
		assign K = '{
				32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5,
				32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
				32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3,
				32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
				32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc,
				32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
				32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7,
				32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
				32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13,
				32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
				32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3,
				32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
				32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5,
				32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
				32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208,
				32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2};
		
		//generate block which governs how much sha mixer is unrolled
		genvar i;
		generate 
			if(N == 1) begin
				//really small design, one passtrough core
				sha_mix_part C(.clk(clk), .index(indexIn), .words(wordsIn), .digest(digestIn), .K(K[indexIn%64]), .wordsOut(wordsOut), .digestOut(digestOut), .indexOut(indexOut));
			end else begin 
				for(i =0; i < N; i++) begin : cores
					wire [31:0] local_words[0:15];
					wire [31:0] local_digest[0:7];
					wire [15:0] local_index;

					//individual cores, cores[index] represents local wires generated for each core (in this case we connect everytime to previous one)
					if(i == 0) begin
						//first core connects mix input with actual one input and mix output with next core output
						sha_mix_part core(.clk(clk), .index(indexIn), .words(wordsIn), .digest(digestIn), .K(K[indexIn%64]), .wordsOut(local_words), .digestOut(local_digest), .indexOut(local_index));
					end else if(i < (N-1)) begin 
						//middle core(s) connect previous core output with actual one input and actual output with next core input
						sha_mix_part core(.clk(clk), .index(cores[i-1].local_index), .words(cores[i-1].local_words), .digest(cores[i-1].local_digest), .K(K[cores[i-1].local_index%64]), .wordsOut(local_words), .digestOut(local_digest), .indexOut(local_index));
					end else begin
						//last core connects previous core output with actual one input and mix output with actual output
						sha_mix_part core(clk, cores[i-1].local_index, cores[i-1].local_words, cores[i-1].local_digest, K[cores[i-1].local_index%64], wordsOut, digestOut, indexOut);
					end
				end
			end
		endgenerate
				
endmodule

//this module is based on this java SHA implementation: https://code.google.com/p/a9cipher/source/browse/src/cosc385final/SHA2.java?r=df621cf75f3448903e9393194a1d6aa086b0a92b
//it works and I am happy! :)
module sha_mix_part(input clk, input[15:0] index, input [31:0] words[0:15], input [31:0] digest[0:7], input [31:0] K, output reg[31:0] wordsOut[0:15], output reg[31:0] digestOut[0:7], output reg[15:0] indexOut);
		
		//TODO resolve long combinational path for ch and newWork - too much chained adders
		
		//digest/state computation for next round part
		wire [31:0] s0;
		wire [31:0] s00;
		wire [31:0] s01;
		wire [31:0] s02;
		
		wire [31:0] s1;
		wire [31:0] s10;
		wire [31:0] s11;
		wire [31:0] s12;
		
		wire [31:0] maj;
		wire [31:0] ch;
		wire [31:0] t2;
		wire [31:0] t1;
		
		always @(*) begin
			s00[31:30] = digest[0][1:0];
			s00[29:0] = digest[0][31:2];
			
			s01[31:19] = digest[0][12:0];
			s01[18:0] = digest[0][31:13];
			
			s02[31:10] = digest[0][21:0];
			s02[9:0] = digest[0][31:22];
			
			
			s10[31:26] = digest[4][5:0];
			s10[25:0] = digest[4][31:6];
			
			s11[31:21] = digest[4][10:0];
			s11[20:0] = digest[4][31:11];
			
			s12[31:7] = digest[4][24:0];
			s12[6:0] = digest[4][31:25];			
		
			maj = (digest[0] & digest[1]) ^ (digest[0] & digest[2]) ^ (digest[1] & digest[2]);
			ch =  (digest[4] & digest[5]) ^ (~digest[4] & digest[6]);
			
			s0 = s00 ^ s01 ^ s02;
			s1 = s10 ^ s11 ^ s12;
			
			t2 = s0+maj;
			
			t1 = digest[7] + s1 + ch + K + words[0];
		end
		//shift digests (internal states)
		always @(posedge clk) begin
			digestOut[0] <= t1 + t2;
			digestOut[1] <= digest[0];
			digestOut[2] <= digest[1];
			digestOut[3] <= digest[2];
			digestOut[4] <= digest[3] + t1;
			digestOut[5] <= digest[4];
			digestOut[6] <= digest[5];
			digestOut[7] <= digest[6];
		end

		//words computation for next round
		wire [31:0] w00;
		wire [31:0] w01;
		wire [31:0] w02;
		
		wire [31:0] w10;
		wire [31:0] w11;
		wire [31:0] w12;
		
		wire [31:0] newWord;
		
		always @(*) begin
			w00[31:25] = words[1][6:0];
			w00[24:0] = words[1][31:7];
				
			w01[31:14] = words[1][17:0];
			w01[13:0] = words[1][31:18];
				
			w02 = words[1] >> 3;
				
			w10[31:15] = words[14][16:0];
			w10[14:0] = words[14][31:17];
				
			w11[31:13] = words[14][18:0];
			w11[12:0] = words[14][31:19];
				
			w12 = words[14] >> 10;
			
			newWord = words[0] + (w00^ w01^w02) + words[9] + (w10 ^ w11 ^ w12);
		end
			
		//words are shifted and last one is updated + index increment
		always @(posedge clk) begin
			wordsOut[15] <=  newWord;
		   for(int i =0; i< 15; i++) begin
				wordsOut[i] <= words[i+1];
			end
			//increment index
			indexOut <= index +1'h1;
		end
endmodule

extern module ram #(parameter elementWidth = 32,	parameter elementCount = 8, parameter depth = 256, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)],	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);
//queue - same as in sha, but different data size
//inspiration taken from altera examples
//this queue now replaces last element if it is full, could be changed, but newer results are ussually better
//anyway it should be never filled, if so we need to change target
module shaqueue(clk, write, read, in, out, available, full);
	parameter elementWidth = 8;
	parameter elementCount = 128;
	parameter depth = 256;
	
	input clk;
	input write;
	input read;
	input [(elementWidth-1):0] in[0:(elementCount-1)];
	output [(elementWidth-1):0] out[0:(elementCount-1)];
	output available;
	output full;
	
	function integer log2(input integer v); 
		begin log2=0; 
		while(v>>log2) 
			log2=log2+1; 
	end endfunction
		
	localparam addrWidth = log2(depth-1);
	
	reg[(addrWidth-1):0] write_addr, read_addr;
	reg[addrWidth:0] count;
	
	ram #(.elementWidth(elementWidth), .elementCount(elementCount), .depth(depth)) ram(clk, in, write_addr, (read & available) ? (read_addr+1) : read_addr, write, out);
	
	initial begin 
		read_addr = 0;
		write_addr = 0;
		count = 0;
	end
	
	//queue is full
	assign full = (count == depth);
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
