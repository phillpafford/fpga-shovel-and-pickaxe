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

package cz.zeno.miner;

import cz.zeno.miner.interfaces.Work;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang.ArrayUtils;

/**
 *
 * @author zeno
 */
public class FpgaWork implements Work {
    byte[] jobID;
    
    byte[] version;
    byte[] prevhash;    
    byte[] merkleRoot;
    
    byte[] nbits;
    byte[] ntime;

    byte[] extranonce2;
    
    byte[] target;
    
    boolean isScrypt;
    
    public FpgaWork(byte[] jobID, byte[] version, byte[] prevhash, byte[] merkleRoot, byte[] nbits, byte[] ntime, byte[] extranonce2, byte[] target, boolean isScrypt) {
        this.jobID = jobID;
        this.version = version;
        this.prevhash = prevhash;
        this.merkleRoot = merkleRoot;
        this.nbits = nbits;
        this.ntime = ntime;
        this.extranonce2 = extranonce2;
        this.target = target;
        this.isScrypt = isScrypt;
    }

    @Override
    public byte[] getWork()
    {
        //original header is extended with custom target and jobid (for miner internals)
        //initial nonce, target, jobID
        try {
            byte[] adder;
            
            //scrypt fpga needs different four bytes from target
            if(isScrypt)
                adder = ArrayUtils.addAll(ArrayUtils.addAll(Utils.hexStringToByteArray("00000000"), ArrayUtils.subarray(target, 2, 6)),jobID);
            else
                adder = ArrayUtils.addAll(ArrayUtils.addAll(Utils.hexStringToByteArray("00000000"), ArrayUtils.subarray(target, 4, 8)),jobID);
            
            byte[] work = ArrayUtils.addAll(ArrayUtils.addAll(ArrayUtils.addAll(Utils.swapEndian(ArrayUtils.addAll(version, prevhash)), merkleRoot), Utils.swapEndian(ArrayUtils.addAll(ntime,nbits))), adder);
            return work;
        } catch (DecoderException ex) {
            Logger.getLogger(FpgaWork.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public byte[] getJobID() {
        return jobID;
    }

    @Override
    public byte[] getExtranonce2() {
        return extranonce2;
    }

    @Override
    public byte[] getNtime() {
        return ntime;
    }

    @Override
    public String getJobIDString() {
        return Utils.byteArrayToHexString(jobID);
    }
    
}
