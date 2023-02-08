package UCB.MICS.InHome;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;

public class Utilities {
    public static Map<String, String> getFromRequest(HttpServletRequest req) throws IOException {
        return new ObjectMapper().readValue(req.getInputStream().readAllBytes(), Map.class);
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
}
