// KeystreamDump.java — reference oracle for the C++ RC4 port.
//
// Lives in the applet's package so it can use the package-private RC4
// constructor / randomValue() / update_key(). Compile against the real jar and
// run; its output must match test_crypto's [RC4] lines byte-for-byte.
//
//   javac -cp rc175p10.jar -d build cpp/KeystreamDump.java
//   java  -cp "rc175p10.jar;build" com.hp.ilo2.remcons.KeystreamDump
package com.hp.ilo2.remcons;

public class KeystreamDump {
    static String dump(RC4 r, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", r.randomValue() & 0xff));
        return sb.toString();
    }

    public static void main(String[] args) {
        byte[] seed = new byte[16];
        for (int i = 0; i < 16; i++) seed[i] = (byte)(i * 17 + 3);

        RC4 r = new RC4(seed);
        System.out.println("initial   " + dump(r, 32));
        r.update_key();                      // TELNET_CHG_ENCRYPT_KEYS
        System.out.println("post-rekey " + dump(r, 32));
    }
}
