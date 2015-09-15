package org.connectbot.simplesocks;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.*;

/**
 * Created by kroot on 9/15/15.
 */
public class Socks5ServerTest {
    @Test(expected = IOException.class)
    public void testAuthentication_NotSocks5_Failure() throws Exception {
        InputStream in = wrapBytes(new byte[] { 0x01, 0x01, 0x00 });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        server.acceptAuthentication();
    }

    @Test
    public void testAuthentication_SingleMethod_Success() throws Exception {
        InputStream in = wrapBytes(new byte[] { 0x05, 0x01, 0x00 });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertTrue(server.acceptAuthentication());
        assertArrayEquals(new byte[] { 0x05, 0x00 }, out.toByteArray());
    }

    @Test
    public void testAuthentication_MultipleMethods_Success() throws Exception {
        InputStream in = wrapBytes(new byte[] { 0x05, 0x03, 0x02, 0x01, 0x00 });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertTrue(server.acceptAuthentication());
        assertArrayEquals(new byte[] { 0x05, 0x00 }, out.toByteArray());
    }

    @Test
    public void testAuthentication_UnsupportedAuth() throws Exception {
        InputStream in = wrapBytes(new byte[] { 0x05, 0x01, 0x02 });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertFalse(server.acceptAuthentication());
        assertArrayEquals(new byte[] { 0x05, (byte) 0xFF }, out.toByteArray());
    }

    private InputStream wrapBytes(byte[] bytes) {
        return new ByteArrayInputStream(bytes);
    }
}