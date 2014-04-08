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

import gnu.io.CommPortIdentifier;
import java.util.ArrayList;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;

/**
 *
 * @author zeno
 */
public class Utils {
     
    //Some utilities, these calls may be used directly, but I separated and placed all of them to this utils class
    //maybe something will be added in future?
    
    //converts hex string to byte array
     public static byte[] hexStringToByteArray(String s) throws DecoderException {
        if(s.length()%2 != 0)
            s = "0" + s;
        return Hex.decodeHex(s.toCharArray());
    }

    //convert to hex string and extend or shrink to specified length
    public static byte[] hexStringToByteArray(String s, int count) throws DecoderException {
        byte[] m = hexStringToByteArray(s);
        byte[] data = new byte[count];

        if(m.length < data.length)
            System.arraycopy(m, 0, data, data.length - m.length, m.length);
        else
            System.arraycopy(m, 0, data, 0, data.length);

        return data;
    }
    
    //reverse proces, byte array to hex string
    public static String byteArrayToHexString(byte[] data)
    {
        return String.valueOf(Hex.encodeHex(data));
//        String ret = "";
//        for(byte bb : data)
//        {
//            ret += String.format("%02X", bb);
//        } 
//        return ret;
    }
        
    //swap endiannes - used!
    public static byte[] swapEndian(byte[] data)
    {
        //reverse each four bytes
        for(int i =0; i < data.length/4; i++)
        {
            byte[] msub = ArrayUtils.subarray(data, i*4, i*4+4);
            ArrayUtils.reverse(msub);
            System.arraycopy(msub, 0, data, i*4, 4);
        }
        return data;
    }
    
    public static String[] getAvailableSerialPorts()
    {
        java.util.Enumeration<CommPortIdentifier> portEnum = CommPortIdentifier.getPortIdentifiers();
        ArrayList<String> serialPorts = new ArrayList<>();
        while ( portEnum.hasMoreElements() ) 
        {
            CommPortIdentifier portIdentifier = portEnum.nextElement();
            
            if(CommPortIdentifier.PORT_SERIAL == portIdentifier.getPortType())
            {
                serialPorts.add(portIdentifier.getName());
            }
        }
        return serialPorts.toArray(new String[0]);
    }
}
