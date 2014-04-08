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
public class HmacPreScryptTest extends AbstractTest{

    public HmacPreScryptTest() {
        super(128);
    }
    
     @Test
     public void hmacPreScryptTest() throws NoSuchAlgorithmException, IOException, DecoderException, InterruptedException 
     {
        OutputStream os = serial.getOutputStream();
        String header = "0200000000E9BB420531937EBF61EF3A3D8F24359F3E14D0E65374EE0000000000000000EA22A241EB40D607CB65B5DC738AD13D85F597C89DD4994BD02FEDCFE9868383D1362753B1020119FFFFFFF0FFFFFFF0000029D4";
        byte[] binheader = Utils.hexStringToByteArray(header);

        int w = 1;
        for(int k = 0; k < 1; k++)
        {
            for(int i = 0; i < 88; i++)
            {
                os.write(binheader[i]);
            }

//                        w++;
            os.flush();
            Thread.sleep(1000);
        }
        os.flush();

        header = "0200000000E9BB420531937EBF61EF3A3D8F24359F3E14D0E65374EE0000000000000000EA22A241EB40D607CB65B5DC738AD13D85F597C89DD4994BD02FEDCFE9868383D1362753B1020119FFFFFFF0";
        binheader = Utils.hexStringToByteArray(header);

        for(int j = 0; j < 16; j++)
        {
            binheader[79] = (byte) (240+j);

            SHA2 sha = new SHA2("SHA-256");
            byte[] opad = new byte[64];
            byte[] inp = sha.digest(binheader);
            System.arraycopy(inp, 0 , opad, 0, 32);
            opad = xor(opad, (byte)0x5C);
            sha.reset();
//
            byte[] ipad = new byte[64];
            System.arraycopy(inp,0 , ipad, 0, 32);
            ipad = xor(ipad, (byte)0x36);


            byte[] block1 = new byte[binheader.length + 4];
            arraycopy(binheader, 0, block1, 0, binheader.length);
            System.err.println();
            for(int k =1; k < 5; k++)
            {
                sha.reset();
//                            block1[binheader.length + 0] = (byte) (0 >> 24 & 0xff);
//                            block1[binheader.length + 1] = (byte) (0 >> 16 & 0xff);
//                            block1[binheader.length + 2] = (byte) (0 >> 8  & 0xff);
                block1[binheader.length + 3] = (byte) (k >> 0  & 0xff);

                byte[] c1 = new byte[148];
                System.arraycopy(ipad,0 , c1, 0, 64);
                System.arraycopy(block1,0 , c1, 64, 84);
                byte[] sha2 = sha.digest(c1);
                sha.reset();
                byte[] d1 = new byte[96];
                System.arraycopy(opad,0 , d1, 0, 64);
                System.arraycopy(sha2, 0 , d1, 64, 32);
                byte[] sha3 = sha.digest(d1);

                for(byte bb : sha3)
                {
//                                System.err.print((0xFF & bb) + "-");
                    System.err.print(String.format("%02X", bb));
                }
            }
        }
        Thread.sleep(1000);

        os.close();
     }
}
