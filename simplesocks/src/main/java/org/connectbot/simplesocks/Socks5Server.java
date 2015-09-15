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

import java.io.*;
import java.net.InetAddress;
import java.nio.charset.Charset;

/**
 * Created by kroot on 9/15/15.
 */
public class Socks5Server {
    /** Address type that indicates the request is IPv4. */
    private static final int ATYPE_IPV4 = 0x01;

    /** Address type that indicates the request is IPv6. */
    private static final int ATYPE_DNS = 0x03;

    /** Address type that indicates the request is IPv6. */
    private static final int ATYPE_IPV6 = 0x04;

    private final DataInputStream in;
    private final DataOutputStream out;

    public enum Command {
        CONNECT(0x01),
        BIND(0x02);

        public static Command fromCommandNumber(int commandNumber) {
            if (commandNumber == Command.CONNECT.commandNumber()) {
                return Command.CONNECT;
            } else if (commandNumber == Command.BIND.commandNumber()) {
                return Command.BIND;
            } else {
                return null;
            }
        }

        private final int commandNumber;

        Command(int commandNumber) {
            this.commandNumber = commandNumber;
        }

        public int commandNumber() {
            return commandNumber;
        }
    }

    public enum ResponseCode {
        SUCCESS((byte) 0x00),
        GENERAL_FAILURE((byte) 0x01),
        RULESET_DENIED((byte) 0x02),
        NETWORK_UNREACHABLE((byte) 0x03),
        HOST_UNREACHABLE((byte) 0x04),
        CONNECTION_REFUSED((byte) 0x05),
        TTL_EXPIRED((byte) 0x06),
        COMMAND_NOT_SUPPORTED((byte) 0x07),
        ADDRESS_TYPE_NOT_SUPPORTED((byte) 0x08);

        private final byte code;

        ResponseCode(byte code) {
            this.code = code;
        }

        public byte getCode() {
            return code;
        }
    }

    /** The command the request is referring to. */
    private Command command;

    /** Address requested when the {@link Command} was given. */
    private InetAddress address;

    /** The port requested when the {@link Command} was given. */
    private int port = -1;

    public Socks5Server(InputStream in, OutputStream out) {
        this.in = new DataInputStream(in);
        this.out = new DataOutputStream(out);
    }

    public boolean acceptAuthentication() throws IOException {
        checkProtocolVersion();

        int numMethods = in.read();
        byte[] methods = new byte[numMethods];
        in.readFully(methods);

        boolean success = false;
        for (byte method : methods) {
            if (method == 0x00) {
                success = true;
                break;
            }
        }

        byte[] reply = new byte[2];
        reply[0] = 0x05;
        if (success) {
            reply[1] = 0x00;
        } else {
            reply[1] = (byte) 0xFF;
        }
        out.write(reply);
        return success;
    }

    private void checkProtocolVersion() throws IOException {
        if (in.read() != 0x05) {
            throw new IOException("Unsupported protocol");
        }
    }

    public boolean readRequest() throws IOException {
        checkProtocolVersion();

        boolean correct = true;

        command = Command.fromCommandNumber(in.read());
        if (command == null) {
            correct = false;
        }

        if (in.read() != 0x00) {
            correct = false;
        }

        int atype = in.read();
        if (atype == ATYPE_IPV4) {
            byte[] addressBytes = new byte[4];
            in.readFully(addressBytes);
            address = InetAddress.getByAddress(addressBytes);
        } else if (atype == ATYPE_DNS) {
            int hostNameLength = in.read();
            byte[] hostName = new byte[hostNameLength];
            in.readFully(hostName);
            address = InetAddress.getByName(new String(hostName, Charset.forName("US-ASCII")));
        } else if (atype == ATYPE_IPV6) {
            byte[] addressBytes = new byte[16];
            in.readFully(addressBytes);
            address = InetAddress.getByAddress(addressBytes);
        } else {
            correct = false;
        }

        port = in.read() << 8 | in.read();

        return correct;
    }

    public void sendReply(ResponseCode response) throws IOException {
        byte[] responseBytes = new byte[]{
                (byte) 0x05, /* version */
                response.getCode(),
                (byte) 0x00, /* reserved */
                (byte) 0x01, /* Address type: IPv4 */
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, /* INADDR_ANY */
                (byte) 0x00, (byte) 0x00, /* port */
        };
        out.write(responseBytes);
    }

    public Command getCommand() {
        return command;
    }

    public InetAddress getAddress() {
        return address;
    }

    public int getPort() {
        return port;
    }
}
