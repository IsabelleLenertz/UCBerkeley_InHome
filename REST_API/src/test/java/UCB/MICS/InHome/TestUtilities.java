package UCB.MICS.InHome;

import javassist.bytecode.ByteArray;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
public class TestUtilities {

    @Test
    public static void testIpV4ToByteArray()
    {
        // Given an IPv4 address
        String ip = "192.168.0.01";
        byte[] expected = new byte[] {
                (byte) 192,
                (byte) 168,
                (byte) 0,
                (byte) 1
        };
        // When IPv4ToByteArray is called
        byte[] actual = Utilities.ipV4ToByteArray(ip);

        // The address is properly converted
        assertEquals(actual, expected);
    }

    @Test
    public static void testMacToByteArray()
    {
        byte[] expected = new byte[] {
                (byte) 136,
                (byte) 102,
                (byte) 90,
                (byte) 6,
                (byte) 127,
                (byte) 16
        };
        byte[] actual1 = Utilities.macToByteArray("88:66:5a:06:7f:10");
        byte[] actual2 = Utilities.macToByteArray("88.66.5a.06.7f.10");
        assertEquals(actual1, expected);
        assertEquals(actual2, expected);
    }
}
