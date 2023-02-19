package UCB.MICS.InHome;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import java.util.Map;

public class Utilities {
    // Same contants use in json requests/responses
    public static String MAC = "mac";
    public static String IPV4 = "ipv4";
    public static String NAME = "name";
    public static String OLD_NAME = "old";
    public static String NEW_NAME = "new";
    public static String DATE_ADDED = "date_added";
    public static String IPV6 = "ipv6";
    public static String IS_TRUSTED = "is_trusted";
    public static String APPLICATION_JSON = "application/json";

    public static Map<String, String> getFromRequest(HttpServletRequest req) throws IOException {

        Iterator<String> it = req.getReader().lines().iterator();
        StringBuilder stringBuilder = new StringBuilder();
        while(it.hasNext()) {
            stringBuilder.append(it.next());
        }
        return new ObjectMapper().readValue(stringBuilder.toString(), Map.class);
        //return new ObjectMapper().readValue(req.getInputStream().readAllBytes(), Map.class);
    }

    public static byte[] ipV4ToByteArray(String ip) throws NumberFormatException
    {
        byte[] ipInBytes = new byte[4];
        String[] elements = ip.split("\\.");
        try {
            for(int i = 0; i < 4; i++) {
                ipInBytes[i] = (byte)(Short.parseShort(elements[i]));
                //ipInBytes[i*2+1] = (byte)(Short.parseShort(elements[i]));
            }
        } catch (Exception e) {
            throw new NumberFormatException();
        }
        return ipInBytes;
    }

    public static byte[] macToByteArray(String mac) throws NumberFormatException
    {
        mac = mac.replace(".", ":");
        String[] elements = mac.split(":");
        byte[] macInBytes = new byte[6];
        for (int i = 0; i < macInBytes.length; i++) {
            try {
                macInBytes[i] = Hex.decodeHex(elements[i])[0];
            } catch (Exception e) {
                throw new NumberFormatException();
            }
        }
        return macInBytes;
    }

    /**
     * converts a byte array (network order) representation of a mac address and returns a legible string
     * @param mac byte array representation (network order) of a mac address
     * @return legible string of the form xx:xx:xx:xx:xx:xx
     */
    public static String byteArrayMacToString(byte[] mac)
    {
    	StringBuilder strBuilder = new StringBuilder();
    	for (int i = 0; i < mac.length; i++) {
    	    strBuilder.append(String.format("%02X", mac[i]));
    	    if (i < mac.length - 1) 
    	        strBuilder.append(":");
    	}
    	return strBuilder.toString();
    }

    /**
     * converts a byte array (network order) representation of a ipv4 address and returns a legible string
     * @param ipv4 byte array representation (network order) of an ipv4 address
     * @return legible string of the form xxx.xxx.xxx.xxx
     */
    public static String byteArrayIpv4ToString(byte[] ipv4)
    {
    	String addressStr = "";
    	for (int i = 0; i < 4; ++i)
    	{
    	    int t = 0xFF & ipv4[i];
    	    addressStr += "." + t;
    	}
    	return addressStr.substring(1);
    }

    /**
     * converts a byte array (network order) representation of a IPv6 address and returns a legible string
     * @param ipv6 byte array representation (network order) of a IPv6 address
     * @return legible string of the form xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
     */
    public static String byteArrayIpv6ToString(byte[] ipv6)
    {
    	StringBuilder strBuilder = new StringBuilder();
    	for (int i = 0; i < ipv6.length; i=i+2) {
    	    strBuilder.append(String.format("%02X", ipv6[i]));
    	    strBuilder.append(String.format("%02X", ipv6[i+1]));
    	    if (i < ipv6.length - 2) 
    	        strBuilder.append(":");
    	}
    	return strBuilder.toString();
    }
}
