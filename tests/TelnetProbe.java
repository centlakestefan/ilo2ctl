// TelnetProbe.java — reference oracle for telnet.hpp.
//
// Drives the REAL applet class com.hp.ilo2.remcons.telnet: opens a loopback
// server that replays build/telnet_stream.bin (produced by test_telnet.cpp),
// lets telnet.run() detect the ESC '[' 'R' trigger and RC4-decrypt the DVC
// payload, and prints the decrypted bytes as hex for comparison with the C++.
//
//   javac -cp rc175p10.jar -d build cpp/TelnetProbe.java
//   java  -cp "rc175p10.jar;build" com.hp.ilo2.remcons.TelnetProbe
//
// Lives in the applet package so it can override the package-private
// process_dvc() and touch the protected `screen` field.
package com.hp.ilo2.remcons;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class TelnetProbe extends telnet {
    private final StringBuffer captured = new StringBuffer();

    TelnetProbe() {
        // Replace the GUI canvas with one whose show_text() is a no-op, so
        // telnet.run() (which calls screen.show_text on a peerless canvas) does
        // not NPE and abort before processing the stream. Everything else in the
        // real run()/decrypt path is exercised unchanged.
        this.screen = new dvcwin(1600, 1200) {
            public void show_text(String s) { /* no-op for headless test */ }
        };
    }

    // Overrides telnet.process_dvc(char): record each decrypted DVC byte.
    boolean process_dvc(char c) {
        captured.append(String.format("%02x", c & 0xff));
        return true; // stay in DVC mode
    }

    static byte[] readAll(String path) throws Exception {
        DataInputStream in = new DataInputStream(new FileInputStream(path));
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        final byte[] stream = readAll("build/telnet_stream.bin");

        final ServerSocket server = new ServerSocket(0);
        final int port = server.getLocalPort();

        Thread srv = new Thread(new Runnable() {
            public void run() {
                try {
                    Socket c = server.accept();
                    OutputStream os = c.getOutputStream();
                    os.write(stream);   // replay the exact bytes the C++ fed
                    os.flush();
                    Thread.sleep(1200);
                    c.close();
                } catch (Exception e) {
                    System.out.println("server error: " + e);
                }
            }
        });
        srv.setDaemon(true);
        srv.start();

        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte)(i * 7 + 1);

        TelnetProbe probe = new TelnetProbe();
        probe.setup_decryption(key);                 // before any DVC byte arrives
        probe.connect("127.0.0.1", "LOGIN", port, 0, 0);  // starts telnet.run() thread

        Thread.sleep(1500);                          // let the stream be processed
        System.out.println("java_dvc " + probe.captured.toString());
        System.exit(0);
    }
}
