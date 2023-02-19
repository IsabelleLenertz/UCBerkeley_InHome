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
        byte[] actual1 = Utilities.macToByteArray("88:66:5A:06:7F:10");
        assertEquals(actual1, expected);
    }

    @Test (enabled = false)
    public static void testByteArrayMacToString()
    {
        String expected = "88:66:5a:06:7f:10";
        String actual = Utilities.byteArrayMacToString(Utilities.macToByteArray(expected));
        assertEquals(actual, expected);
    }

    @Test (enabled = false)
    public static void testByteArrayIpv4ToString()
    {
        String expected = "192.168.0.01";
        String actual = Utilities.byteArrayIpv4ToString(Utilities.ipV4ToByteArray(expected));
        assertEquals(actual, expected);
    }

    @Test (enabled = false)
    public static void testByteArrayIpv6ToString()
    {
        String expected = "FFFF:AA12:BB00:42CC:9956:34B5:AAFF:FFAA";
        String actual = Utilities.byteArrayIpv6ToString(
                new byte[] {
                        (byte) 0xFF,
                        (byte) 0xFF,
                        (byte) 0xAA,
                        (byte) 0x12,
                        (byte) 0xBB,
                        (byte) 0x00,
                        (byte) 0x42,
                        (byte) 0xCC,
                        (byte) 0x99,
                        (byte) 0x56,
                        (byte) 0x34,
                        (byte) 0xB5,
                        (byte) 0xAA,
                        (byte) 0xFF,
                        (byte) 0xFF,
                        (byte) 0xAA,
                }
        );
        assertEquals(actual, expected);
    }
}
