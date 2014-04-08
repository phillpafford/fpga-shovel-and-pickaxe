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
public class ShaMinerTest extends AbstractTest{

    public ShaMinerTest() {
        super(32);
    }
    
     @Test
     public void shaMinerTest() throws NoSuchAlgorithmException, IOException, DecoderException, InterruptedException 
     {
        OutputStream os = serial.getOutputStream();

        SHA2 sha1 = new SHA2("SHA-256");
        SHA2 sha2 = new SHA2("SHA-256");

        int w = 0;
        for(int k = 0; k < 1; k++)
        {
            String header = "0200000000E9BB420531937EBF61EF3A3D8F24359F3E14D0E65374EE0000000000000000EA22A241EB40D607CB65B5DC738AD13D85F597C89DD4994BD02FEDCFE9868383D1362753B1020119FFFFFF00FFFFFFF0000029D4";
        //                        String header = "01000000" + "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000" + "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b" +"c7f5d74d" + "f2b9441a" + "FF000000" + "FFFFFFFFFF000000" + String.format("%02X", w) + "000000";
            byte[] binheader = Utils.hexStringToByteArray(header);

            for(int i = 0; i < 88; i++)
            {
                os.write(binheader[i]);
            }
            w++;
            os.flush();

            System.err.println();
        }
        os.flush();

        Thread.sleep(1000);

        os.close();
     }
}
