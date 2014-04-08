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

import cz.zeno.miner.interfaces.Appender;
import cz.zeno.miner.interfaces.Server;
import cz.zeno.miner.interfaces.Work;
import cz.zeno.miner.interfaces.Worker;
import gnu.io.CommPort;
import gnu.io.CommPortIdentifier;
import gnu.io.SerialPort;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang.ArrayUtils;
import sun.security.pkcs11.wrapper.Constants;

/**
 *
 * @author zeno
 */
public final class FpgaSerial implements Worker
{
    SerialPort serialPort;
    SerialReader sr;
    Thread serailThread;
    Server server;
    Appender appender;
    
    //this class is communication layer for sha miner (and future scrypt) miners
    //it implements Worker interface - thus StratumClient can command it
    //it needs two interfaces to be passed to constructor - Server for work related issues and Appender for status output
    public FpgaSerial(String device, Server server, Appender appender) {
        this.server = server;
        this.appender = appender;
        
        try {
            //this is part of constructor, we do not need to do it manually
            connect(device, 5000);
        } catch (Exception ex) {
            Logger.getLogger(FpgaSerial.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    //open serial port which is connected to fpga device
    //serial port parameters must match on the device side!
    private void connect (String portName, int threshold) throws Exception
    {
        CommPortIdentifier portIdentifier = CommPortIdentifier.getPortIdentifier(portName);
        if ( portIdentifier.isCurrentlyOwned() )
        {
            appender.append("Error: Port is currently in use");
        }
        else
        {
            //from RXTX examples
            CommPort commPort = portIdentifier.open(this.getClass().getName(),2000);

            if (commPort instanceof SerialPort)
            {
                //set up serial port
                serialPort = (SerialPort) commPort;
                serialPort.enableReceiveTimeout(threshold);
                serialPort.setSerialPortParams(115200,SerialPort.DATABITS_8,SerialPort.STOPBITS_2,SerialPort.PARITY_NONE);

                //start async reader
                sr = new SerialReader(serialPort, server);
                serailThread = new Thread(sr);
                serailThread.start();
            }
            else
            {
                appender.append("Error: Only serial ports are handled by this example.");
            }
        }     
    }

    //
    boolean stopped = false;
    boolean stop = false;
    public void stop() throws InterruptedException, DecoderException
    {
        //schedule stop work
        String stopWork = "";
        for(int i = 0; i < 76; i++)
        {
            stopWork += "00";
        }
        //last nonce stops miner
        stopWork += "FFFFFFFF";
        //blank nonce
        stopWork += "00000000" + "00000000";
        stop = true;
        scheduleWork(Utils.hexStringToByteArray(stopWork));
        sr.stop();
        serailThread.join();
        serialPort.close();
    }
    
    private final Object submitLock = new Object();
    
    LinkedHashMap<String, Work> jobToWork = new LinkedHashMap<>();
    
    @Override
    public void scheduleWork(Work w) {
        //register work
        jobToWork.put(w.getJobIDString(), w);
        //drop some historical work
        if(jobToWork.size() > 100)
        {
            for(int i = 0; i < 20; i++)
            {
                jobToWork.remove(jobToWork.keySet().iterator().next());
            }
        }
        //send it to fpga
        scheduleWork(w.getWork());
    }

    private void scheduleWork(byte[] binheader) {
        synchronized(submitLock)
        {
            //bad header! take into account, that original bitcoin header is extended with target and jobID (additional 8B)
            if(binheader.length != 88)
            {
                appender.append("wrong work data length" + Constants.NEWLINE);
                return;
            }
            //stop switch, after this nothing can be scheduled
            if(stopped)
               return;
            if(stop)
                stopped = true;
            
            //get new output stream and send data
            OutputStream os = null;
            try {
                os = serialPort.getOutputStream();
                for(int k = 0; k < 1; k++)
                {
                    for(int i = 0; i < 88; i++)
                    {
                        os.write(binheader[i]);
                    }
                } 
                os.flush();
                //select jobID from header and print it
                String out = "";
                for(int i = 84; i < 88; i++)
                {
                    out += String.format("%02X", binheader[i]);
                }  
                appender.append("new job set :" + out + Constants.NEWLINE);
                
            } catch (IOException ex) {
                Logger.getLogger(FpgaSerial.class.getName()).log(Level.SEVERE, null, ex);

            } finally {
                try {
                    if(os != null)
                        os.close();
                } catch (IOException ex) {
                    Logger.getLogger(FpgaSerial.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }
    
    //this reader listens to incomming traffic from fpga
    private class SerialReader implements Runnable 
    {
        boolean stop = false;
        SerialPort serialPort;
        InputStream in;
        Server server;

        public SerialReader (SerialPort serialPort,Server submitter) throws IOException
        {
            this.server = submitter;
            this.serialPort = serialPort;
            this.in = serialPort.getInputStream();
        }

        public void stop() {
            this.stop = true;
            try {
                in.close();
            } catch (IOException ex) {
                Logger.getLogger(FpgaSerial.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        @Override
        public void run ()
        {
            //well, there is nothing special in this
            //just parse incomming data, and decide wheter request new work or submit share
            byte[] buffer = new byte[64];

            int len;
            try
            {
                int zerocounter = 0;
                byte[] result = null;
                while (!stop)
                {
                    len = in.read(buffer);

                    if(len > 0)
                    {
                        //if there were some bytes left from last read, append them at the begining of next bytes received
                        if(result == null)
                            result = Arrays.copyOf(buffer, len);
                        else
                            result = ArrayUtils.addAll(result, Arrays.copyOf(buffer, len));

                        //TODO enhance stram parsing, for example if there are some remaining data, it screws results...
                        //so - recognize jobId pattern and align results again or something like that
                        
                        if(result.length >= 8)
                        {
                            ByteBuffer bb = ByteBuffer.wrap(result);

                            for(int i = 0; i < 8; i++)
                            {
                                if(result[i] == 0)
                                {
                                    zerocounter++;
                                }
                            }
                            //eight zeros mean that fpga run to end of nonce interval
                            if(zerocounter == 8)
//                            if(ByteBuffer.wrap(ArrayUtils.subarray(bb.array(), 4, 8)).getInt(0) == 0xffffffff)
                            {
                                server.requestNewWork(FpgaSerial.this);
                            }
                            //otherwise regular submit
//                            if(zerocounter != 8)
                            else
                            {
//                                String s = "";
//                                for(byte b : bb.array())
//                                {
//                                    s += String.format("%02X", b);
//                                }  
//                                System.out.println("submit " + s);
                                
                                server.submitShare(jobToWork.get(Utils.byteArrayToHexString(ArrayUtils.subarray(bb.array(), 0, 4))), Utils.swapEndian(ArrayUtils.subarray(bb.array(), 4, 8)));
                            }

                            //store bytes which were out of 8B interval
                            if(result.length == 8)
                                result = null;
                            else
                                result = Arrays.copyOfRange(result, 8, result.length);

                            zerocounter = 0;
                        }
                    }
//                    Thread.sleep(50);
                }
            }
            catch (IOException e)
            {
                if(!stop)
                    //unintentional
                    Logger.getLogger(SerialReader.class.getName()).log(Level.SEVERE, null, e);
            }  
            finally
            {
                try {
                    in.close();
                } catch (IOException ex) {
                    if(!stop)
                        //unintentional
                        Logger.getLogger(SerialReader.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

        }
    }
}
