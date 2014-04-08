/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cz.zeno.miner.test;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author zeno
 */
public abstract class AbstractTest {
    
    Serial serial;
    int newLineAfter;
    public AbstractTest(int newLineAfter) {
        this.newLineAfter = newLineAfter;
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
        serial = new Serial(newLineAfter);
    }
    
    @After
    public void tearDown() {
        //waits for some keystroke
//        try {
//            while(System.in.available() == 0)
//            {
//                Thread.sleep(100);
//            }
//        } catch (Exception ex) {
//            Logger.getLogger(AbstractTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
         
        try {
            serial.stop();
        } catch (InterruptedException ex) {
            Logger.getLogger(AbstractTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static byte[] xor(byte[] data, byte xor)
    {
        byte[] buffer = new byte[data.length]; 

        for (int i = 0; i < data.length; i++)
            buffer[i] = (byte) (data[i] ^ xor);

        return buffer;
    }
}
