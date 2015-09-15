package org.connectbot.simplesocks;

import java.io.*;

/**
 * Created by kroot on 9/15/15.
 */
public class Socks5Server {
    private final DataInputStream in;
    private final DataOutputStream out;

    public Socks5Server(InputStream in, OutputStream out) {
        this.in = new DataInputStream(in);
        this.out = new DataOutputStream(out);
    }

    public boolean acceptAuthentication() throws IOException {
        if (in.read() != 0x05) {
            throw new IOException("Unsupported protocol");
        }

        int numMethods = in.read();
        byte[] methods = new byte[numMethods];
        in.readFully(methods);

        boolean success = false;
        for (int i = 0; i < methods.length; i++) {
            if (methods[i] == 0x00) {
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
}
