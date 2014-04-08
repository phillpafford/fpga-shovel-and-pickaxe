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
public class HmacPostScryptTest extends AbstractTest{

    public HmacPostScryptTest() {
        super(32);
    }
    
     @Test
     public void hmacPostScryptTest() throws NoSuchAlgorithmException, IOException, DecoderException, InterruptedException 
     {
         byte[] B = new byte[128];

        OutputStream os = serial.getOutputStream();
        //send compute instruction
        for(int a = 0; a < 32; a++)
        {
            int w = a;
            for(int k = 0; k < 1; k++)
            {
                for(int i = 0; i < 128; i++)
                {
                    B[i] = (byte)(i+w);
                    os.write(B[i]);
                }
                w++;
                os.flush();
            }
            os.flush();
            w = 2;

//
            SHA2 sha = new SHA2("SHA-256");
            byte[] opad = new byte[64];
//                    byte[] inp = sha.digest(C);
//                    System.arraycopy(inp, 0 , opad, 0, 32);
            opad = xor(opad, (byte)0x5C);
            sha.reset();
//
            byte[] ipad = new byte[64];
//                    System.arraycopy(inp,0 , ipad, 0, 32);
            ipad = xor(ipad, (byte)0x36);


            System.err.println();

            byte[] c1 = new byte[196];
            System.arraycopy(ipad,0 , c1, 0, 64);
            System.arraycopy(B,0 , c1, 64, 128);
            c1[195] = 1;
            byte[] sha2 = sha.digest(c1);
            sha.reset();
            byte[] d1 = new byte[96];
            System.arraycopy(opad,0 , d1, 0, 64);
            System.arraycopy(sha2, 0 , d1, 64, 32);
            byte[] sha3 = sha.digest(d1);


            for(byte bb : sha3)
            {
//                        System.err.print((0xFF & bb) + "-");
                System.err.print(String.format("%02X", bb));
            }
        }

        Thread.sleep(1000);

        os.close();
     }
}
