/*
 * simplesocks
 * Copyright 2015 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
        ByteArrayInputStream in = wrapBytes((byte) 0x01, (byte) 0x01, (byte) 0x00);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        server.acceptAuthentication();
    }

    @Test
    public void testAuthentication_SingleMethod_Success() throws Exception {
        getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00);
    }

    private Socks5Server getAuthenticatedSocks5Server(byte... input) throws IOException {
        InputStream in = wrapBytes(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertTrue(server.acceptAuthentication());
        assertArrayEquals(new byte[]{0x05, 0x00}, out.toByteArray());
        return server;
    }

    @Test
    public void testAuthentication_MultipleMethods_Success() throws Exception {
        InputStream in = wrapBytes((byte) 0x05, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x00);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertTrue(server.acceptAuthentication());
        assertArrayEquals(new byte[]{0x05, 0x00}, out.toByteArray());
    }

    @Test
    public void testAuthentication_UnsupportedAuth() throws Exception {
        InputStream in = wrapBytes(new byte[] { 0x05, 0x01, 0x02 });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        assertFalse(server.acceptAuthentication());
        assertArrayEquals(new byte[] { 0x05, (byte) 0xFF }, out.toByteArray());
    }

    @Test(expected = IOException.class)
    public void testReadRequest_InvalidProtocol_Failure() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01);
        assertTrue(server.readRequest());
        assertArrayEquals(new byte[]{(byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01}, server.getAddress().getAddress());
    }

    @Test(expected = IOException.class)
    public void testReadRequest_InvalidReserved_Failure() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x01, (byte) 0x01, (byte) 0x10, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01);
        assertTrue(server.readRequest());
        assertArrayEquals(new byte[]{(byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01}, server.getAddress().getAddress());
    }

    @Test
    public void testReadRequest_UnknownCommand_Failure() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0xC0, (byte) 0x00, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01);
        assertFalse(server.readRequest());
        assertEquals(null, server.getCommand());
    }

    @Test
    public void testReadRequest_ConnectIPv4_Success() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01,
                (byte) 0x07, (byte) 0xD1);
        assertTrue(server.readRequest());
        assertEquals(Socks5Server.Command.CONNECT, server.getCommand());
        assertArrayEquals(new byte[]{(byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01}, server.getAddress().getAddress());
        assertEquals(2001, server.getPort());
    }

    @Test
    public void testReadRequest_ConnectDNS_Success() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x01, (byte) 0x00, (byte) 0x03, (byte) 0x0B, (byte) 'e', (byte) 'x', (byte) 'a',
                (byte) 'm', (byte) 'p', (byte) 'l', (byte) 'e', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm',
                (byte) 0x22, (byte) 0xB8);
        assertTrue(server.readRequest());
        assertEquals(Socks5Server.Command.CONNECT, server.getCommand());
        assertEquals("example.com", server.getAddress().getHostName());
        assertEquals(8888, server.getPort());
    }

    @Test
    public void testReadRequest_ConnectIPv6_Success() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x01, (byte) 0x00, (byte) 0x04,
                /* IPv6 address; 32 bits on a row. */
                (byte) 0x20, (byte) 0x01, (byte) 0x0D, (byte) 0xB8,
                (byte) 0xA5, (byte) 0x5A, (byte) 0xFF, (byte) 0x02,
                (byte) 0xCC, (byte) 0xAA, (byte) 0x01, (byte) 0x10,
                (byte) 0x00, (byte) 0x00, (byte) 0xD0, (byte) 0x0D,
                /* port */
                (byte) 0x3F, (byte) 0xAE);
        assertTrue(server.readRequest());
        assertEquals(Socks5Server.Command.CONNECT, server.getCommand());
        assertArrayEquals(new byte[]{(byte) 0x20, (byte) 0x01, (byte) 0x0D, (byte) 0xB8,
                (byte) 0xA5, (byte) 0x5A, (byte) 0xFF, (byte) 0x02,
                (byte) 0xCC, (byte) 0xAA, (byte) 0x01, (byte) 0x10,
                (byte) 0x00, (byte) 0x00, (byte) 0xD0, (byte) 0x0D}, server.getAddress().getAddress());
        assertEquals(16302, server.getPort());
    }

    @Test
    public void testReadRequest_BindIPv4_Success() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x02, (byte) 0x00, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01,
                /* port */
                (byte) 0x04, (byte) 0x38);
        assertTrue(server.readRequest());
        assertEquals(Socks5Server.Command.BIND, server.getCommand());
        assertArrayEquals(new byte[]{(byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01}, server.getAddress().getAddress());
        assertEquals(1080, server.getPort());
    }

    @Test
    public void testReadRequest_InvalidReservedByte_Failure() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01);
        assertFalse(server.readRequest());
    }

    @Test
    public void testReadRequest_ConnectUnknownProtocol_Failure() throws Exception {
        Socks5Server server = getAuthenticatedSocks5Server((byte) 0x05, (byte) 0x01, (byte) 0x00,
                (byte) 0x05, (byte) 0x01, (byte) 0x00, (byte) 0xA8, (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01);
        assertFalse(server.readRequest());
    }

    @Test
    public void testSendReply_Success() throws IOException {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Socks5Server server = new Socks5Server(in, out);
        server.sendReply(Socks5Server.ResponseCode.SUCCESS);
        assertArrayEquals(new byte[] {
                (byte) 0x05, /* version */
                (byte) 0x00, /* code */
                (byte) 0x00, /* reserved */
                (byte) 0x01, /* atype (IPv4) */
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, /* address */
                (byte) 0x00, (byte) 0x00}, /* port */
                out.toByteArray());
    }

    private ByteArrayInputStream wrapBytes(byte... bytes) {
        return new ByteArrayInputStream(bytes);
    }
}
