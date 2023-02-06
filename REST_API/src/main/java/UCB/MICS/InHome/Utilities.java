package UCB.MICS.InHome;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

public class Utilities {
    public static Map<String, String> getFromRequest(HttpServletRequest req) throws IOException {
        return new ObjectMapper().readValue(req.getInputStream().readAllBytes(), Map.class);
    }

    public static byte[] ipToByteArray(String ip) throws NumberFormatException
    {
        byte[] ipInBytes = new byte[8];
        String[] elements = ip.split("\\.");
        try {
            for(int i = 0; i < 4; i++) {
                ipInBytes[i*2] = (byte)(Integer.parseInt(elements[i]) >>> 8);
                ipInBytes[i*2+1] = (byte)(Integer.parseInt(elements[i]));
            }
        } catch (Exception e) {
            throw new NumberFormatException();
        }
        return ipInBytes;
    }

    public static byte[] macToByteArray(String mac) throws NumberFormatException
    {
        return null;
    }
}
