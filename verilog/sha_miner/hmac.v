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

//behold :)

module hmac_prescrypt(input clk, input doWork, input [7:0] available, input [7:0] in[0:79], input [31:0] job, output reg[7:0] scryptResultOut[0:127], output reg[31:0] scryptResultJobOut, output reg[31:0] scryptResultNonceOut, output reg[31:0] scryptPadOut[0:7], output reg scryptResultAvailable);
	//unroll parameter
	parameter unroll = 64;

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
	reg[31:0] padOut[0:7];
	reg[31:0] digestOutOriginal[0:7];
	wire [31:0] digestIn [0:7];
	wire [31:0] padIn [0:7];
	wire [31:0] digestInOriginal [0:7];
	
	//wires for first phase midstate computation
	//second part with 12 header bytes + nonce and padding
	wire[7:0] firstStageSecondPart[0:63];
	wire[7:0] midstateSecondPart[0:63];
	
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
	hmac_pipeline #(unroll) hmacp(clk,  stateOut, digestOut, digestOutOriginal, wordsOut, jobOut, nonceOut, padOut, digestIn, digestInOriginal, wordsIn, stateIn, jobIn, nonceIn, padIn);
	
	//digest stored for one stage cycle in the middle of computation
	wire[31:0] midDigestOut[0:7];
	hmacqueue #(.elementWidth(32), .elementCount(8), .depth(unroll + 1)) dq(clk, secondBlockPartReady, opadHashed, newDigest, midDigestOut);
	
	//new nonce register
	reg[31:0] newNonce;
	
	//work counter
	reg[2:0] workCounter;
	reg [7:0] preparing;

	//combinationals needed to assemble new data to hash (paddings, nonces...)	
	wire[7:0] blockPadding[0:63];
	wire[7:0] midDigestPadding[0:63];
	wire [31:0] newDigest[0:7];
	always @(*) begin
		for(int i =0; i < 8; i++) begin
			newDigest[i] = (digestIn[i] + digestInOriginal[i]);	
		end
	
		//this is maybe not the best way to set things up, but i find this way readable and easy to understand
		firstStageSecondPart[0:11] = workBuffer[64:75];
		//assembly nonce for new sha hashing
		firstStageSecondPart[8'd15] = newNonce;
		firstStageSecondPart[8'd14] = (newNonce >>> 8);
		firstStageSecondPart[8'd13] = (newNonce >>> 16);
		firstStageSecondPart[8'd12] = (newNonce >>> 24);
		
		//padding to 128 bytes of 80B input (first stage second sha part)
		firstStageSecondPart[8'd16] = 128;
		for(int i =1; i < 46; i++) begin
			firstStageSecondPart[16+i] = 0;
		end
		firstStageSecondPart[8'd62] = 2;
		firstStageSecondPart[8'd63] = 128;
		
		midstateSecondPart[0:11] = firstStageSecondPart[0:11];
		midstateSecondPart[8'd15] = nonceIn;
		midstateSecondPart[8'd14] = (nonceIn >>> 8);
		midstateSecondPart[8'd13] = (nonceIn >>> 16);
		midstateSecondPart[8'd12] = (nonceIn >>> 24);
		midstateSecondPart[16:63] = firstStageSecondPart[16:63];
		
		//extended block padding
		blockPadding[0:11] = workBuffer[64:75];
		blockPadding[8'd15] = nonceIn;
		blockPadding[8'd14] = (nonceIn >>> 8);
		blockPadding[8'd13] = (nonceIn >>> 16);
		blockPadding[8'd12] = (nonceIn >>> 24);
		
		blockPadding[8'd16] = 0;
		blockPadding[8'd17] = 0;
		blockPadding[8'd18] = 0;
		blockPadding[8'd19] = stateIn[18:16];
		blockPadding[8'd20] = 8'd128;
		for(int i =21; i < 60; i++) begin
			blockPadding[i] = 8'd0;
		end
		blockPadding[8'd60] = 0;
		blockPadding[8'd61] = 0;
		blockPadding[8'd62] = 4;
		blockPadding[8'd63] = 160;

		//opad and first part digest padding
		for(int i =0; i < 8; i++) begin
			midDigestPadding[i*4 + 3] = midDigestOut[i];
			midDigestPadding[i*4 + 2] = (midDigestOut[i] >>> 8);
			midDigestPadding[i*4 + 1] = (midDigestOut[i] >>> 16);
			midDigestPadding[i*4] = (midDigestOut[i] >>> 24);
		end
		midDigestPadding[32] = 128;
		for(int i =33; i < 60; i++) begin
			midDigestPadding[i] = 0;
		end	
		midDigestPadding[60] = 0;
		midDigestPadding[61] = 0;
		midDigestPadding[62] = 3;
		midDigestPadding[63] = 0;
	end
	
	//some states to be easilly readable
	wire pipelineWorkIn = stateIn[31] & (jobIn == currentJob);
	wire pipelineReady = (~pipelineWorkIn | resultReady);
	
	wire midstateStageReady = (stateIn[15:0] == 64) & (jobIn == currentJob);
	wire paddingReady = (stateIn[15:0] == 128) & (jobIn == currentJob);
	wire ipadHashed = (stateIn[15:0] == 192) & (jobIn == currentJob);
	wire firstBlockPartReady = (stateIn[15:0] == 256) & (jobIn == currentJob);
	wire secondBlockPartReady = (stateIn[15:0] == 320) & (jobIn == currentJob);
	wire opadHashed = ((stateIn[15:0] == 384) & (jobIn == currentJob)) | ((jobIn != currentJob) & (stateIn[15:0] > 320) & (stateIn[15:0] <= 384));
	wire resultReady = (stateIn[15:0] == 448) & (jobIn == currentJob);
	
	//without actual job control, better for performance
//	wire pipelineWorkIn = stateIn[31];
//	wire pipelineReady = (~pipelineWorkIn | resultReady);
//	
//	wire midstateStageReady = (stateIn[15:0] == 64);
//	wire paddingReady = (stateIn[15:0] == 128);
//	wire ipadHashed = (stateIn[15:0] == 192);
//	wire firstBlockPartReady = (stateIn[15:0] == 256);
//	wire secondBlockPartReady = (stateIn[15:0] == 320);
//	wire opadHashed = ((stateIn[15:0] == 384));
//	wire resultReady = (stateIn[15:0] == 448);
	
	//  & (jobIn == currentJob)
	reg decreasePrepare;
	
	always@(posedge clk) begin
		if(doWork) begin
			//set new data
			workBuffer <= in;
			//set new job
			currentJob <= job;
			//reset nonce 
			//concatenation of input bytes in header
			newNonce <= {in[76],in[77],in[78],in[79]};
			
			//new midstate must be computed
			midstateReady <= 0;
			
			//if there is job control, we can null preparing counter
			preparing <= 0;
			
			//set schedule flag
			scheduleTask <= 1;
			//null work counter 
			workCounter <= 0;
		end
	
	
		if(pipelineReady) begin
			if(scheduleTask & (preparing < available)) begin
				//now we can schedule task, there is something to do! :) as always in life!
				if(~midstateReady) begin
					//begining of new work - there is no midstate known
					//midstate is the same result of first 64 bytes part sha transform; (because of nonce, which changes, lies at bytes 76-79 [zero index])
					//--> concatenation
					for(int i =0; i<16; i++) begin
						wordsOut[i] <= (workBuffer[4*i] <<< 24) | (workBuffer[4*i + 1] <<< 16) | (workBuffer[4*i + 2] <<< 8) | (workBuffer[4*i + 3]); 
					end
					//empty pad out
					for(int i =0; i<8; i++) begin
						padOut[i] <= 0; 
					end
					//set state variables					
					stateOut[31] <= 1;
					stateOut[15:0] <= 0;
					
					//set up other job infos
					jobOut <= currentJob;
					nonceOut <= newNonce;
					
					//there are four jobs queued for one nonce - this prescrypt hmac part outputs 128 bytes
					//work counter signals when it is needed to nonce
					stateOut[18:16] <= workCounter + 1'h1;
					if(workCounter == 3) begin
						workCounter <= 0;
						
						newNonce <= newNonce + 1;
						if(newNonce == (32'hffffffff)) begin
							scheduleTask <= 0;
						end
					end else begin
						workCounter <= workCounter + 1'd1;
					end
					
					//set initial digest
					digestOut <= H;
					digestOutOriginal <= H;
				end else begin
					//new work scheduling is in stage, where midstate is known (first sha done)
					stateOut[31] <= 1;
					
					for(int i =0; i<8; i++) begin
						padOut[i] <= 0; 
					end
					
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
					
					//there are four jobs queued for one nonce - this prescrypt hmac part outputs 128 bytes
					//work counter signals when it is needed to nonce
					stateOut[18:16] <= workCounter + 1'd1;
					if(workCounter == 3) begin
						workCounter <= 0;
						newNonce <= newNonce + 1;
						if(newNonce == (32'hffffffff)) begin
							scheduleTask <= 0;
						end
					end else begin
						workCounter <= workCounter + 1'd1;
					end
					
					//we continue from state 64 (midstate is known)
					stateOut[15:0] <= 64;
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
				for(int i =0; i<8; i++) begin
					padOut[i] <= 0; 
				end
				
			end
		end
		
		if(pipelineWorkIn) begin
			if(midstateStageReady) begin
				//this state is possible only at the several beginning cycles, when there is no midstate...
				//continue to second data part and set midstate, so that we do not need to go trough this stage for this job anymore
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				midstate <= newDigest;	
				
				//second part of data mix stored in queue
				//concatenate/assemble words variable
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (midstateSecondPart[4*i] <<< 24) | (midstateSecondPart[4*i + 1] <<< 16) | (midstateSecondPart[4*i + 2] <<< 8) | (midstateSecondPart[4*i + 3]); 
				end
				
				//set job info states etc.
				stateOut <= stateIn;
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				padOut <= padIn;	
				
				//mark midstate ready for this job
				midstateReady <= 1;
			end else if(paddingReady) begin
				//opad and ipad source is now ready, do hash on ipad
				//reset digest
				digestOut <= H;
				digestOutOriginal <= H;
				
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up words.
				//new digest is padding source, xor it with ipad constant (0x36)
				for(int i =0; i < 8; i++) begin
					padOut[i] <= newDigest[i];	
					wordsOut[i] <= newDigest[i] ^ 32'h36363636;	
					wordsOut[8+i] <= 32'h36363636;	
				end
			end else if(ipadHashed) begin
				//ipad is hashed, continue with block data
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//set state variables
				stateOut <= stateIn;
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				
				//set up words.
				//concatenate block data from work buffer, first part
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (workBuffer[4*i] <<< 24) | (workBuffer[4*i + 1] <<< 16) | (workBuffer[4*i + 2] <<< 8) | (workBuffer[4*i + 3]); 
				end				
			end  else if(firstBlockPartReady) begin
				//firs block part is hashed, continue with secon padded part and new digest
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//set state variables
				stateOut <= stateIn;
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				
				//set up words.
				//concatenate second padded part of block data
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (blockPadding[4*i] <<< 24) | (blockPadding[4*i + 1] <<< 16) | (blockPadding[4*i + 2] <<< 8) | (blockPadding[4*i + 3]); 
				end				
			end else if(secondBlockPartReady) begin
				//second padded part of block is hashed now, its digest is also stored to queue
				//reset digest
				digestOut <= H;	
				digestOutOriginal <= H;	

				//set state variables
				stateOut <= stateIn;
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				
				//set up words.
				//xor pad source so that we obtain opad
				for(int i =0; i < 8; i++) begin
					wordsOut[i] <= padIn[i] ^ 32'h5C5C5C5C;	
					wordsOut[8+i] <= 32'h5C5C5C5C;	
				end				
			end else if(opadHashed) begin
				//opad part hash is ready, continue mixing with current digest
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	

				//set state variables
				stateOut <= stateIn;
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				
				//set up words.
				//words are filled from padded stored digest from middle hmac stage
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (midDigestPadding[4*i] <<< 24) | (midDigestPadding[4*i + 1] <<< 16) | (midDigestPadding[4*i + 2] <<< 8) | (midDigestPadding[4*i + 3]); 
				end						
			end else if(resultReady) begin
				//one of final parts is ready
				for(int i =0; i < 8; i++) begin
					scryptResultOut[(stateIn[18:16] - 1)*32 + i*4 + 3] <= newDigest[i];
					scryptResultOut[(stateIn[18:16] - 1)*32 + i*4 + 2] <= (newDigest[i] >>> 8);
					scryptResultOut[(stateIn[18:16] - 1)*32 + i*4 + 1] <= (newDigest[i] >>> 16);
					scryptResultOut[(stateIn[18:16] - 1)*32 + i*4] <= (newDigest[i] >>> 24);	
				end
				scryptResultJobOut <= jobIn;
				scryptResultNonceOut <= nonceIn;
				scryptPadOut <= padIn;
			end else begin
				//some middle phase, continue mixing
				wordsOut <= wordsIn;
				digestOut <= digestIn;
				digestOutOriginal <= digestInOriginal;
				stateOut <= stateIn;
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				padOut <= padIn;
			end
		end
		
		//if result ready, signal it to module connected to output
		if((resultReady & (stateIn[18:16] == 4))) begin
			scryptResultAvailable <= 1;
			//decrease prepare after one cycle - so connected module can react 
			//and change its available state - so that we do not begin with preparation too early
			decreasePrepare <= 1;
		end else begin
			scryptResultAvailable <= 0;
			decreasePrepare <= 0;
		end
		
		//increment preparing counter
		if(pipelineReady & scheduleTask & (workCounter == 3) & ~decreasePrepare & ~doWork) begin
			preparing <= preparing +1;
		end
		
		//it is safe now to decrease count of items being prepared
		if(~(pipelineReady & scheduleTask & (workCounter == 3)) & decreasePrepare & ~doWork) begin
			preparing <= preparing - 1;
		end
	end
	
endmodule

module hmac_postscrypt(input clk, input doWork,  input [7:0] in[0:127], input [31:0] job, input [31:0] nonce, input[31:0] pad[0:7] , output reg[7:0] resultOut[0:31], output reg[31:0] resultJobOut, output reg[31:0] resultNonceOut, output reg resultAvailable);
	//unroll parameter
	parameter unroll = 4;

	//sha initial digest constant
	wire [31:0] H [0:7];
	//initial digest (sha state)
	assign H = '{32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};

	//actual work registers
	reg[7:0] workBuffer[0:127];
	reg[7:0] workFirstPart[0:63];
	reg[7:0] workSecondPart[0:63];

	reg[31:0] midstate[0:7];
	
	//signals that there is task to be scheduled
	reg scheduleTask;
	
	//interconnection wires and regs for first pipeline follow
	//task state wire and reg
	reg[31:0] stateOut;
	wire[31:0] stateIn;

	//digest wires and registers
	reg[31:0] digestOut[0:7];
	reg[31:0] padOut[0:7];
	reg[31:0] digestOutOriginal[0:7];
	wire [31:0] digestIn [0:7];
	wire [31:0] padIn [0:7];
	wire [31:0] digestInOriginal [0:7];
	
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
	hmac_pipeline #(unroll) hmacp(clk,  stateOut, digestOut, digestOutOriginal, wordsOut, jobOut, nonceOut, padOut, digestIn, digestInOriginal, wordsIn, stateIn, jobIn, nonceIn, padIn);
	
	//work was scheduled to pipeline, so drop it
	wire dropWork = pipelineReady & workAvailable;
	wire[7:0] queuedWork[0:127];
	wire [31:0] queuedPad [0:7];
	wire [31:0] queuedJob;
	wire [31:0] queuedNonce;
	wire workAvailable;
	
	//in the middle of process, we need to store digest for some time -> queue it
	wire[31:0] midDigestOut[0:7];
	hmacqueue #(.elementWidth(32), .elementCount(8), .depth(8)) dq(clk, blockPaddingReady, opadPartReady, newDigest, midDigestOut);
	
	//we need to know block data later in computation process, so store it to queue
	hmacqueue #(.elementWidth(8), .elementCount(64), .depth(8)) ws1(clk, doWork, ipadPartReady, in[0:63], workFirstPart);
	hmacqueue #(.elementWidth(8), .elementCount(64), .depth(8)) ws2(clk, doWork, firstBlockPartReady, in[64:127], workSecondPart);
	
	//queues/buffers work from scrypt mix (just in case there will be more inputs)
	hmacqueue_packed #(.elementWidth(32), .depth(8)) jq(clk, doWork, dropWork, job, queuedJob);
	hmacqueue_packed #(.elementWidth(32), .depth(8)) nq(clk, doWork, dropWork, nonce, queuedNonce);
	hmacqueue #(.elementWidth(32), .elementCount(8), .depth(8)) pq(clk, doWork, dropWork, pad, queuedPad, workAvailable);
	
	//combinationals needed to assemble new data to hash (paddings, nonces...)
	wire[7:0] blockPadding[0:63];
	wire[7:0] midDigestPadding[0:63];
	wire [31:0] newDigest[0:7];
	always @(*) begin
		//new digest, needed usually in each stage of computation
		for(int i =0; i < 8; i++) begin
			newDigest[i] = (digestIn[i] + digestInOriginal[i]);	
		end
		
		//ipad and block padding
		blockPadding[0] = 0;
		blockPadding[1] = 0;
		blockPadding[2] = 0;
		blockPadding[3] = 1;
		blockPadding[4] = 128;
		for(int i =5; i < 60; i++) begin
			blockPadding[i] = 0;
		end	
		blockPadding[60] = 0;
		blockPadding[61] = 0;
		blockPadding[62] = 6;
		blockPadding[63] = 32;

		//opad and first part digest padding
		for(int i =0; i < 8; i++) begin
			midDigestPadding[i*4 + 3] = midDigestOut[i];
			midDigestPadding[i*4 + 2] = (midDigestOut[i] >>> 8);
			midDigestPadding[i*4 + 1] = (midDigestOut[i] >>> 16);
			midDigestPadding[i*4] = (midDigestOut[i] >>> 24);
		end
		midDigestPadding[32] = 128;
		for(int i =33; i < 60; i++) begin
			midDigestPadding[i] = 0;
		end	
		midDigestPadding[60] = 0;
		midDigestPadding[61] = 0;
		midDigestPadding[62] = 3;
		midDigestPadding[63] = 0;
	end
	
	//some state vars, just to be easily readable
	wire pipelineWorkIn = stateIn[31];
	wire pipelineReady = ~pipelineWorkIn | resultReady;
	
	//translate states to something more readable
	wire ipadPartReady = (stateIn[15:0] == 64);
	wire firstBlockPartReady = (stateIn[15:0] == 128);
	wire secondBlockPartReady = (stateIn[15:0] == 192);
	wire blockPaddingReady = (stateIn[15:0] == 256);
	wire opadPartReady = (stateIn[15:0] == 320);
	wire resultReady = (stateIn[15:0] == 384);
	
	always@(posedge clk) begin
		if(pipelineReady) begin
			if(workAvailable) begin
				//now we can schedule new task, there is something to do! :) as always in life!
				//--> concatenation
				for(int i =0; i<8; i++) begin
					wordsOut[i] <= queuedPad[i] ^ 32'h36363636;	
					wordsOut[8+i] <= 32'h36363636;	
				end
				
				//set state variables					
				stateOut[31] <= 1;
				stateOut[15:0] <= 0;
				
				//set up other job infos
				jobOut <= queuedJob;
				nonceOut <= queuedNonce;
				padOut <= queuedPad;
				
				//set initial digest
				digestOut <= H;
				digestOutOriginal <= H;
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
				for(int i =0; i<8; i++) begin
					padOut[i] <= 0; 
				end
				
			end
		end 
		
		if(pipelineWorkIn) begin
			if(ipadPartReady) begin
				//first sha is complete (sha from ipad from first prescrypt hmac part), 
				//use its digest and scrypt output block data as next input 
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//continue shifting other states
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up words.
				//concatenate some bytes, could be written also like {x,x,x,x}, but copiler result is the same anyway
				//work is from first shift 
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (workFirstPart[4*i] <<< 24) | (workFirstPart[4*i + 1] <<< 16) | (workFirstPart[4*i + 2] <<< 8) | (workFirstPart[4*i + 3]); 
				end				
			end  else if(firstBlockPartReady) begin
				//first sha is complete, use its final digest and info as input for second sha pipeline
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//set states
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up words
				//concatenate next work part, work from second longer shift
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (workSecondPart[4*i] <<< 24) | (workSecondPart[4*i + 1] <<< 16) | (workSecondPart[4*i + 2] <<< 8) | (workSecondPart[4*i + 3]); 
				end				
			end else if(secondBlockPartReady) begin
				//second block digest ready, finish padding 
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
				
				//continue shifting other states
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up words.
				//concatenate some stages
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (blockPadding[4*i] <<< 24) | (blockPadding[4*i + 1] <<< 16) | (blockPadding[4*i + 2] <<< 8) | (blockPadding[4*i + 3]); 
				end						
			end else if(blockPaddingReady) begin
				//second part of hmac, reset digest, process opad
				digestOut <= H;	
				digestOutOriginal <= H;	
				
				//continue shifting other states
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up opad words.
				//create opad and set up words from it
				for(int i =0; i < 8; i++) begin
					wordsOut[i] <= padIn[i] ^ 32'h5C5C5C5C;	
					wordsOut[8+i] <= 32'h5C5C5C5C;	
				end				
			end else if(opadPartReady) begin
				//opad hashed, and now finally process padded digest from middle stage
				digestOut <= newDigest;	
				digestOutOriginal <= newDigest;	
								
				//set state variables
				padOut <= padIn;	
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				stateOut <= stateIn;
				
				//set up final words.
				//concatenate mid digest to form new words
				for(int i =0; i<16; i++) begin
					wordsOut[i] <= (midDigestPadding[4*i] <<< 24) | (midDigestPadding[4*i + 1] <<< 16) | (midDigestPadding[4*i + 2] <<< 8) | (midDigestPadding[4*i + 3]); 
				end						
			end else if(resultReady) begin
				//result is ready, whole cycle finished
				for(int i =0; i < 8; i++) begin
					resultOut[i*4 + 3] <= newDigest[i];
					resultOut[i*4 + 2] <= (newDigest[i] >>> 8);
					resultOut[i*4 + 1] <= (newDigest[i] >>> 16);
					resultOut[i*4] <= (newDigest[i] >>> 24);	
				end
				resultJobOut <= jobIn;
				resultNonceOut <= nonceIn;
			end else begin
				//some middle phase, continue mixing
				wordsOut <= wordsIn;
				digestOut <= digestIn;
				digestOutOriginal <= digestInOriginal;
				stateOut <= stateIn;
				jobOut <= jobIn;
				nonceOut <= nonceIn;
				padOut <= padIn;
			end
		end
		//signal result available
		resultAvailable <= resultReady;
	end
	
endmodule

extern module parameterized_shift_unpacked #(parameter elementWidth = 8, parameter depth = 8,	parameter elementCount = 64) (input clk, input [(elementWidth-1):0] in[0:(elementCount-1)], output [(elementWidth-1):0] out[0:(elementCount-1)]);

extern module sha_mix #(parameter N = 4)(input clk,input[15:0] indexIn, input [31:0] wordsIn[0:15], input [31:0] digestIn[0:7], output [31:0] digestOut[0:7],output [31:0] wordsOut[0:15], output[15:0] indexOut);

//I believe it is readable and easy to understand
module hmac_pipeline(input clk,  input [31:0] stateIn, input[31:0] digestIn[0:7], input[31:0] digestInOriginal[0:7], input [31:0] wordsIn[0:15], input [31:0] jobIn, input [31:0] nonceIn, input[31:0] padIn[0:7], output [31:0] digestOutNew[0:7], output [31:0] digestOutOriginal[0:7], output [31:0] wordsOut[0:15], output [31:0] stateOut, output  [31:0] jobOut, output  [31:0] nonceOut, output [31:0] padOut[0:7]);
	
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
	parameterized_shift_unpacked #(.elementWidth(32), .elementCount(8),.depth(N)) db4(clk, padIn, padOut);
	
	//sha unrolled according to the N parameter
	sha_mix #(N) mix(clk, stateIn[15:0], wordsIn, digestIn, digestOutNew, wordsOut, stateMidm);
	
	//apply new index to state if needed (ie. there was valid task in pipeline)
	assign stateOut = {stateMid[31:16], stateMid[31] ? stateMidm : 16'h00};
	
endmodule

extern module ram #(parameter elementWidth = 8,	parameter elementCount = 64, parameter depth = 4, parameter addrWidth = log2(depth))	(input clk,	input [(elementWidth-1):0] data[0:(elementCount-1)],	input [(addrWidth-1):0] write_addr,	input [(addrWidth-1):0] read_addr,	input we,	output [(elementWidth-1):0] q[0:(elementCount-1)]);
//queue - same as in sha, but different data size
//inspiration taken from altera examples
//this queue now replaces last element if it is full, could be changed, but newer results are ussually better
//anyway it should be never filled, if so we need to change target
module hmacqueue(clk, write, read, in, out, available, full);
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
			write_addr <= write_addr + 1'h1;
			read_addr <= read_addr +1'h1;
		//write only case
		end else if(write) begin
			write_addr <= write_addr + 1'h1;
			//this causes rewrite of oldest value
			if(~full) begin
				count <= count +1'h1;
			end
		//drop only case
		end else if(read & available) begin
			read_addr <= read_addr + 1'h1;
			count <= count - 1'h1;
		end 
	end
endmodule

// parameterized queue tailored for hmac
module hmacqueue_packed(clk, write, read, in, out, available, full, size);
	parameter elementWidth = 8;
	parameter elementCount = 128;
	parameter depth = 256;
	
	input clk;
	input write;
	input read;
	input [(elementWidth-1):0] in;
	output [(elementWidth-1):0] out;
	output available;
	output full;
	output [addrWidth:0] size;
	
	function integer log2(input integer v); 
		begin log2=0; 
		while(v>>log2) 
			log2=log2+1; 
	end endfunction
		
	localparam addrWidth = log2(depth-1);
	
	reg[(addrWidth-1):0] write_addr, read_addr;
	reg[addrWidth:0] count;
	
	ram_packed #(.elementWidth(elementWidth), .depth(depth)) ram(clk, in, write_addr, (read & available) ? (read_addr+3'h1) : read_addr, write, out);
	
	initial begin 
		read_addr = 0;
		write_addr = 0;
		count = 0;
	end
	
	//queue is full
	assign full = (count == depth);
	//some elements available
	assign available = (count > 0);
	
	assign size = depth - count;
	
	always@(posedge clk) begin
		//put, drop and available case
		if(write & read & available) begin
			write_addr <= write_addr + 1'h1;
			read_addr <= read_addr +1'h1;
		//write only case
		end else if(write) begin
			write_addr <= write_addr + 1'h1;
			//this causes rewrite of oldest value
			if(~full) begin
				count <= count +1'h1;
			end
		//this is drop only case
		end else if(read & available) begin
			read_addr <= read_addr + 1'h1;
			count <= count - 1'h1;
		end 
	end
endmodule
