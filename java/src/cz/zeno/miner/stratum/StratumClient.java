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
package cz.zeno.miner.stratum;

import cz.zeno.miner.FpgaWork;
import cz.zeno.miner.ui.MinerUI;
import cosc385final.SHA2;
import cz.zeno.miner.interfaces.Appender;
import cz.zeno.miner.interfaces.Server;
import cz.zeno.miner.interfaces.Worker;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang.ArrayUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import cz.zeno.miner.Utils;
import cz.zeno.miner.interfaces.Work;
import org.apache.commons.codec.DecoderException;
import sun.security.pkcs11.wrapper.Constants;

/**
 *
 * @author zeno
 */
public class StratumClient extends Thread implements Server
    {
        String subscriptionDetails;
        
        byte[] coinb1;
        byte[] coinb2;
    
        byte[] jobID;
    
        byte[] version;
        byte[] prevhash;    

        byte[] nbits;
        byte[] ntime;
    
        byte[] target;
        
        List<byte[]> merkle_branch = new ArrayList<>();
        
        byte[] extranonce1;
        Integer extranonce2 = 0;
        int extranonce2_size;
        
    
        static final Object merkleLock = new Object();
    
        Socket socket;
        OutputStream outputStream;
        InputStream inputStream;
        StratumHandler handler;
        Thread handlerThread;
        
        String name, password;
        Appender appender;
        
        boolean canBuildWork = false;
        
        boolean isScrypt = false;
        //simple constructor, all what StratumClient needs for its work
        //appender is used to show some output states
        public StratumClient(Appender appender, String address, int port, String name, String password, boolean isScrypt) throws IOException {
            //initial target
            this.target = new byte[] {(byte)255,(byte)255,(byte)255,(byte)255};
            socket = new Socket(address, port);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            this.name = name;
            this.password = password;
            this.appender = appender;
            this.isScrypt = isScrypt;
        }
        
        //list of registered workers
        private final Object workerLock = new Object();
        List<Worker> workers = new ArrayList<>();
        
        //register worker
        //new work will be immediatelly sent to worker
        public void registerWorker(Worker worker) {
            synchronized(workerLock)
            {
                workers.add(worker);
                if(canBuildWork)
                    requestNewWork(worker);
            }
        }
        
        //unregister worker
        public void unregisterWorker(Worker worker) {
            synchronized(workerLock)
            {
                workers.remove(worker);
            }
        }

        //sclose stratum client and its listener
        public void close() throws IOException, InterruptedException
        {
            //unauthorize should be implemented
            handler.stop();
            //wait for handler exit
            handlerThread.join();
            
            outputStream.close();
            socket.close();
        }
        
        //connect to stratum
        public void connect() throws IOException
        {
            //create JSON request
            JSONObject obj=new JSONObject();
            
            obj.put("id",new Integer(1));
            obj.put("method","mining.subscribe");
            
            JSONArray params = new JSONArray();
            obj.put("params",params);
            //append to network stream
            new OutputStreamWriter(outputStream).append(obj.toJSONString() + Constants.NEWLINE).flush();
        }
        
        //authorize with stratum
        private void authorize(String workername, String password) throws IOException
        {
            //create JSON request
            JSONObject obj=new JSONObject();
            
            obj.put("id",new Integer(2));
            obj.put("method","mining.authorize");
            
            JSONArray params = new JSONArray();
            params.add(workername);
            params.add(password);
            obj.put("params",params);
            //append to network stream
            new OutputStreamWriter(outputStream).append(obj.toJSONString() + Constants.NEWLINE).flush();
        }

        //submit share to stratum
        //beware! nonce must be in little endian, worker is responsible for this!
        @Override
        public void submitShare(Work work, byte[] nonce) 
        {
            JSONObject obj=new JSONObject();

            obj.put("id",new Integer(4));
            obj.put("method","mining.submit");

            //fill params
            JSONArray params = new JSONArray();
            params.add(name);
            params.add(Utils.byteArrayToHexString(work.getJobID()).toLowerCase().replaceFirst("^0+(?!$)", ""));
            params.add(Utils.byteArrayToHexString(work.getExtranonce2()).toLowerCase());
            params.add(Utils.byteArrayToHexString(work.getNtime()).toLowerCase());
            params.add(Utils.byteArrayToHexString(nonce).toLowerCase());

            obj.put("params",params);

            //append to network stream
            try {
                new OutputStreamWriter(outputStream).append(obj.toJSONString() + Constants.NEWLINE).flush();
            } catch (IOException ex) {
                Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            //inform appender (UI, commandline whatever) about submit
            appender.append("submitting nonce: " + Utils.byteArrayToHexString(Utils.swapEndian(nonce)).toLowerCase() + Constants.NEWLINE);
        }
        
        //all workers should start new work
        private void informWorkers() {
            //if not ready, do nothing
            if(!canBuildWork)
                return;
            synchronized(workerLock)
            {
                for(Worker w : workers)
                    requestNewWork(w);
            }
        }
        
        //miner wants new work, build it and schedule
        @Override
        public void requestNewWork(Worker worker)
        {
            if(worker == null || !canBuildWork)
                return;
            
            FpgaWork w;
            try {
                //build new work
                w = buildWork();
//                String s = "";
//                for(byte b : w.getWork())
//                {
//                    s += String.format("%02X", b);  
//                }
//                System.out.println("schedule " + s);
                //schedule it
                worker.scheduleWork(w);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        //start stratum client
        @Override
        public synchronized void start() {
            try {
                //handler listens for new messages from stratum server
                handler = new StratumHandler(inputStream);
                handlerThread = new Thread(handler);
                handlerThread.start();

                connect();
            } catch (IOException ex) {
                Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        //handles incomming data from stratum server
        class StratumHandler implements Runnable {
            InputStream inputStream;
            boolean stop = false;
            
            StratumHandler(InputStream inputStream) 
            {
                this.inputStream = inputStream;
            }

            public void stop() {
                //stop work
                this.stop = true;
                try {
                    inputStream.close();
                } catch (IOException ex) {
                    //why? what happend?
                    Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            @Override
            public void run() {
                //json parser is reused
                JSONParser parser=new JSONParser();
                while(!stop)
                {
                    byte[] receivedData = new byte[4096];
                    try
                    {
                        int length = inputStream.read(receivedData);
                        if(length == -1)
                            continue;
                        receivedData = Arrays.copyOf(receivedData, length);

                    }
                    catch(IOException e)
                    {
                        if(!stop)
                            //in this state, it was not intended
                            Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, e);
                        break;
                    }
                    
                    //sometimes there are several messages concatenated together, so split them
                    for(String messageToParse : split(new String(receivedData)))
                    {
                        try {
                            //parse message
                            JSONObject message = (JSONObject) parser.parse(messageToParse);
                            parser.reset();
                            
                            if(message.get("id") != null && (Long)message.get("id") == 1 && message.get("error") == null)
                            {
                                try {
                                    //good process fist stage
                                    authorize(name, password);
                                } catch (IOException ex) {
                                    Logger.getLogger(MinerUI.class.getName()).log(Level.SEVERE, null, ex);
                                }
                                JSONArray result = (JSONArray) message.get("result");

                                //parse values from message
                                subscriptionDetails = result.get(0).toString();
                                extranonce1 = Utils.hexStringToByteArray(result.get(1).toString());
                                extranonce2_size = Integer.parseInt(result.get(2).toString());
                            }
                            else if(message.get("id") != null && (Long)message.get("id") == 2 && (Boolean)message.get("result") == true)
                            {
                                //good worker, authorized, process
                                appender.append("worker authorized!" + Constants.NEWLINE);
                            }
                            else if(message.get("id") != null && (Long)message.get("id") == 10)
                            {
                                //exception
                                appender.append("error: " + message.get("error") + Constants.NEWLINE);
                            }
                            else if(message.get("id") == null && "mining.notify".equals((String)message.get("method")))
                            {
                                //good set params for new work
                                JSONArray newwork = (JSONArray) message.get("params");

                                //TODO it should be better to map stratum jobs to some internal job ids
                                //but it is enough for now
//                                System.out.println("acquired job :" + newwork.get(0).toString());
                                jobID = Utils.hexStringToByteArray(newwork.get(0).toString(), 4);

                                prevhash = Utils.hexStringToByteArray(newwork.get(1).toString());
                                coinb1 = Utils.hexStringToByteArray(newwork.get(2).toString());
                                coinb2 = Utils.hexStringToByteArray(newwork.get(3).toString());
                                JSONArray merkle = (JSONArray) newwork.get(4);

                                merkle_branch.clear();
                                for(int i = 0; i < merkle.size(); i++)
                                {
                                    merkle_branch.add(Utils.hexStringToByteArray(merkle.get(i).toString()));
                                }
                                version = Utils.hexStringToByteArray(newwork.get(5).toString());
                                nbits = Utils.hexStringToByteArray(newwork.get(6).toString());
                                ntime = Utils.hexStringToByteArray(newwork.get(7).toString());

                                //testing :), here is place for some experiments
                                //for example, large neural networks should be able to predict nonces
                                //extranonce2 = Integer.parseInt(Utils.byteArrayToHexString(extranonce1), 16);
                                extranonce2 = 0;

                                canBuildWork = true;
                                
                                //clean jobs? if so, immediatelly set new work
                                if((boolean)newwork.get(8))
                                {
                                    informWorkers();
                                }

                            }
                            else if(message.get("id") == null && "mining.set_difficulty".equals((String)message.get("method")))
                            {
                                //good set difficulty for next job
                                JSONArray params = (JSONArray) message.get("params");
                                //TODO decide about proper target format
                                if(isScrypt)
                                    target = ArrayUtils.addAll(ArrayUtils.addAll(Utils.hexStringToByteArray("0000"), ByteBuffer.allocate(2).putShort(0, (short)(0xffffL/(Long)params.get(0))).array()),Utils.hexStringToByteArray("00000000000000000000000000000000000000000000000000000000"));
                                else
                                    target = ArrayUtils.addAll(ArrayUtils.addAll(Utils.hexStringToByteArray("00000000"), ByteBuffer.allocate(2).putShort(0, (short)(0xffffL/(Long)params.get(0))).array()),Utils.hexStringToByteArray("0000000000000000000000000000000000000000000000000000"));
                                
                                appender.append("difficulty changed to:" + params.get(0) + Constants.NEWLINE);
                            }
                            else if(message.get("id") != null && (Long)message.get("id") == 4)
                            {
                                //work status
                                if(message.get("error") == null && (Boolean)message.get("result") == true)
                                {
                                    appender.append("share accepted! "  + Constants.NEWLINE);
                                }
                                else if(message.get("result") == null && message.get("error") != null)
                                {
                                    appender.append("error: " + message.get("error") + Constants.NEWLINE);
                                }
                            }
                            else
                            {
                                //what happened? for future debug...
                                appender.append(message.toString() + Constants.NEWLINE);
                            }
                        } catch (ParseException ex) {
                            //sometimes at the beginning malformed data occur
                            Logger.getLogger(MinerUI.class.getName()).log(Level.SEVERE, null, ex);
                            System.err.println("error, malformed data: " + new String(receivedData));
                        } catch (DecoderException ex) {
                            Logger.getLogger(StratumClient.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }

                }
            }
            
            //split data by }
            public String[] split(String data)
            {
                String[] split = data.split("}");
                
                String[] ret = new String[split.length - 1];
                
                for(int i = 0; i < split.length - 1; i++)
                {
                    ret[i] = split[i] + "}";
                }
                return ret;
            }

        }
        
        //build coinbase transaction from received coinbase data (soublesha)
        private byte[] buildCoinbase(byte[] extranonce2) throws NoSuchAlgorithmException {
            SHA2 sha1 = new SHA2("SHA-256");
            SHA2 sha2 = new SHA2("SHA-256");
//            System.out.println("coinb1: " + Utils.byteArrayToHexString(coinb1));
//            System.out.println("enonce1: " + Utils.byteArrayToHexString(extranonce1));
//            System.out.println("enonce2: " + Utils.byteArrayToHexString(extranonce2));
//            System.out.println("coinb2: " + Utils.byteArrayToHexString(coinb2));
            
            byte[] coinbase_hash_bin = ArrayUtils.addAll(ArrayUtils.addAll(coinb1, extranonce1), ArrayUtils.addAll(extranonce2, coinb2));
//            System.out.println("length: " + coinbase_hash_bin.length);
            return sha2.digest(sha1.digest(coinbase_hash_bin));
        }
                
        //build merkle root from branches and root coinbase hash
        private byte[] buildMerkleRoot(byte[] extranonce2) throws NoSuchAlgorithmException
        {
            SHA2 sha1 = new SHA2("SHA-256");
            SHA2 sha2 = new SHA2("SHA-256");

            byte[] merkleRoot = buildCoinbase(extranonce2);
            for(byte[] branch : merkle_branch)
            {
//                System.out.println("branch: " + Utils.byteArrayToHexString(branch));
                merkleRoot = sha2.digest(sha1.digest(ArrayUtils.addAll(merkleRoot, branch)));
            }

            return merkleRoot;
        }

        //append all data to new work item
        private FpgaWork buildWork() throws NoSuchAlgorithmException
        {
            synchronized(merkleLock)
            {
                byte[] enonce2 = ByteBuffer.allocate(extranonce2_size).putInt(extranonce2).array();
                extranonce2++;
                return new FpgaWork(jobID,version, prevhash, buildMerkleRoot(enonce2), nbits, ntime, enonce2, target, isScrypt);
            }
        }
        
        
       
    }
