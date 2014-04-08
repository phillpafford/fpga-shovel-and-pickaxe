/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cz.zeno.miner.test;

import cosc385final.SHA2;
import cz.zeno.miner.Utils;
import java.io.IOException;
import java.io.OutputStream;
import static java.lang.System.arraycopy;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.DecoderException;
import org.junit.Test;

/**
 *
 * @author zeno
 */
public class ScryptTest extends AbstractTest{

    public ScryptTest() {
        super(32);
    }
    
     @Test
     public void scryptTest() throws NoSuchAlgorithmException, IOException, DecoderException, InterruptedException 
     {
        int r = 1;
        int N = 1024;

        byte[] V  = new byte[128 * r * N];

        OutputStream os = serial.getOutputStream();
        //send compute instruction
//                    os.write(1);
//                    os.flush();
        String header = "01000000" + "ae178934851bfa0e83ccb6a3fc4bfddff3641e104b6c4680c31509074e699be2" + "bd672d8d2199ef37a59678f92443083e3b85edef8b45c71759371f823bab59a9" +"7126614f" + "44d5001d" + "FFFF0000" + "FFFFFFFF" + "10000000";
//                    String header = "01000000" + "ae178934851bfa0e83ccb6a3fc4bfddff3641e104b6c4680c31509074e699be2" + "bd672d8d2199ef37a59678f92443083e3b85edef8b45c71759371f823bab59a9" +"7126614f" + "44d5001d" + "45920180" + "00FFFFFF" + "10000000";
        byte[] binheader = Utils.hexStringToByteArray(header);

        int w = 2;
        for(int k = 0; k < 1; k++)
        {
            binheader[85] += k;
            for(int i = 0; i < 88; i++)
            {
                os.write(binheader[i]);
            }
            w++;
            os.flush();
            Thread.sleep(1000);
        }
        os.flush();
        w = 2;
//                    binheader = hexStringToByteArray("01000000" + "ae178934851bfa0e83ccb6a3fc4bfddff3641e104b6c4680c31509074e699be2" + "bd672d8d2199ef37a59678f92443083e3b85edef8b45c71759371f823bab59a9" +"7126614f" + "44d5001d" + "45920180");
//                    for(int k = 0; k < 4; k++)
//                    {
////                        for(int i = 0; i < 80; i++)
////                        {
////                            B[i] = (byte)(i+w);
////                            XY[i] = (byte)(i+w);
////                        }
//                        binheader[79] += k;
////                        w++;
//                        System.err.println();
//                        for(byte bb : Serial.scryptJ2(binheader, binheader, 1024, 1, 1, 32))
//                        {
//    //                        System.err.print(bb + "-");
//                              System.err.print((0xFF & bb) + "-");
//                        }
//                    }

//                    
////                    Thread.sleep(500);
////
//                    SHA2 sha = new SHA2("SHA-256");
//                    byte[] opad = new byte[64];
//                    byte[] inp = sha.digest(C);
//                    System.arraycopy(inp, 0 , opad, 0, 32);
//                    opad = xor(opad, (byte)0x5C);
//                    sha.reset();
////
//                    byte[] ipad = new byte[64];
//                    System.arraycopy(inp,0 , ipad, 0, 32);
//                    ipad = xor(ipad, (byte)0x36);
//                    
//
//                    byte[] block1 = new byte[C.length + 4];
//                    arraycopy(C, 0, block1, 0, C.length);
//                    System.err.println();
//                    byte[] input = new byte[128];
//                    for(int k =1; k < 5; k++)
//                    {
//                        sha.reset();
//                        block1[C.length + 0] = (byte) (k >> 24 & 0xff);
//                        block1[C.length + 1] = (byte) (k >> 16 & 0xff);
//                        block1[C.length + 2] = (byte) (k >> 8  & 0xff);
//                        block1[C.length + 3] = (byte) (k >> 0  & 0xff);
//
//                        byte[] c1 = new byte[148];
//                        System.arraycopy(ipad,0 , c1, 0, 64);
//                        System.arraycopy(block1,0 , c1, 64, 84);
//                        byte[] sha2 = sha.digest(c1);
//                        sha.reset();
//                        byte[] d1 = new byte[96];
//                        System.arraycopy(opad,0 , d1, 0, 64);
//                        System.arraycopy(sha2, 0 , d1, 64, 32);
//                        byte[] sha3 = sha.digest(d1);
//
//                        
//                        for(byte bb : sha3)
//                        {
//                            System.err.print((0xFF & bb) + "-");
//                        }
//                    }

//                    byte[] sha3 = sha.digest(C);
//
//                    System.err.println();
//                    for(byte bb : sha3)
//                    {
//                        System.err.print((0xFF & bb) + "-");
//                    }


        Thread.sleep(100);

        os.close();
     }
}
