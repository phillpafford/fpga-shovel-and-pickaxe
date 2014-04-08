/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cz.zeno.miner.test;

import gnu.io.CommPort;
import gnu.io.CommPortIdentifier;
import gnu.io.SerialPort;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author zeno
 */
public class Serial {
        
    private SerialPort serialPort;
    private Serial.SerialReader sr;
    private Thread serialThread;
    
    public Serial(int newLineAfter) {
        try {
            connect("/dev/ttyUSB0", 5000, newLineAfter);
        } catch (Exception ex) {
            Logger.getLogger(Serial.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public OutputStream getOutputStream() throws IOException
    {
        return serialPort.getOutputStream();
    }
    
    public void connect ( String portName, int threshold, int newLineAfter) throws Exception
    {
        CommPortIdentifier portIdentifier = CommPortIdentifier.getPortIdentifier(portName);
        if ( portIdentifier.isCurrentlyOwned() )
        {
            System.out.println("Error: Port is currently in use");
        }
        else
        {
            CommPort commPort = portIdentifier.open(this.getClass().getName(),2000);

            if ( commPort instanceof SerialPort )
            {
                serialPort = (SerialPort) commPort;
                serialPort.enableReceiveTimeout(threshold);
                serialPort.setSerialPortParams(115200,SerialPort.DATABITS_8,SerialPort.STOPBITS_2,SerialPort.PARITY_NONE);

                sr = new SerialReader(serialPort, newLineAfter, System.currentTimeMillis());
                serialThread = new Thread(sr);
                serialThread.start();

            }
            else
            {
    //                    arrayco
                System.out.println("Error: Only serial ports are handled by this example.");
            }
        }
    }
    
    public void stop() throws InterruptedException
    {
        sr.setStop(true);
        serialThread.join();
    }
    
    public class SerialReader implements Runnable 
    {
        boolean stop = false;
        int newLineAfter = 128;
        InputStream in;
        long start;
        public SerialReader (SerialPort serialPort, int newLineAfter, long start) throws IOException
        {
            this.newLineAfter = newLineAfter;
            in = serialPort.getInputStream();
            this.start = start;
        }

        public void setStop(boolean stop) {
            this.stop = stop;
        }



        public void run ()
        {
            byte[] buffer = new byte[1024];
            int len = -1;
            try
            {
                System.out.println();
                int c = 0;
                int zerocounter = 0;
                while (!stop)
                {
                    len = in.read(buffer);

                    if(len > 0)
                    {
                        for(int i = 0; i < len; i++)
                        {
                            System.out.print(String.format("%02X", buffer[i]));
//                              System.out.print((0xFF & buffer[i]) + "-");
                            c++;
                            if(c == newLineAfter)
                            {
                                System.out.println();
                                c = 0;
                            }
                            if(buffer[i] == 0)
                            {
                                zerocounter++;
                            }
                            else 
                                zerocounter = 0;

                            if(zerocounter == newLineAfter)
                            {
                                System.out.println("computation took: " + (System.currentTimeMillis() - start)/1000 + " seconds");
                            }
                        }
//                            System.out.println();
                    }
                    Thread.sleep(50);
                }

            }
            catch ( Exception e )
            {
                e.printStackTrace();
            }  
            finally
            {
                try {
                    in.close();
                } catch (IOException ex) {
                    Logger.getLogger(Serial.class.getName()).log(Level.SEVERE, null, ex);
                }
                serialPort.close();
            }

        }
    }
}
