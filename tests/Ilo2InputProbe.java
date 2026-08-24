// Ilo2InputProbe.java — reference oracle for ilo2_input.hpp.
//
// Mouse encoders: capture the plaintext cim.transmit() argument for
// serverMove/send_mouse_press/send_mouse_release/mouse_mode_change/send_ctrl_alt_del.
// Keyboard: printable chars via LocaleTranslator.translate (en_US); controls and
// special keys via cim.translate_key / translate_special_key. Output must match
// test_ilo2_input's build/input_cpp.txt.
//
//   javac -cp rc175p10.jar -d build cpp/Ilo2InputProbe.java
//   java  -cp "rc175p10.jar;build" com.hp.ilo2.remcons.Ilo2InputProbe
package com.hp.ilo2.remcons;

import java.awt.Canvas;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.io.PrintWriter;
import java.lang.reflect.Field;

public class Ilo2InputProbe {

    // Captures the plaintext transmit() argument as hex (no encryption path).
    static class CapCim extends cim {
        String last = "";
        public void transmit(String s) {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < s.length(); i++) b.append(String.format("%02x", s.charAt(i) & 0xff));
            last = b.toString();
        }
    }

    static String hex(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) b.append(String.format("%02x", s.charAt(i) & 0xff));
        return b.toString();
    }

    public static void main(String[] args) throws Exception {
        CapCim c = new CapCim();
        c.setLocale("en_US");
        c.set_mouse_protocol(1);                       // absolute
        Field sx = cim.class.getDeclaredField("screen_x"); sx.setAccessible(true);
        Field sy = cim.class.getDeclaredField("screen_y"); sy.setAccessible(true);
        sx.setInt(c, 800); sy.setInt(c, 600);

        Component src = new Canvas();
        PrintWriter w = new PrintWriter("build/input_java.txt");

        int[][] coords = {{0,0},{400,300},{799,599},{123,456}};
        for (int[] p : coords) { c.serverMove(0, 0, p[0], p[1]); w.println("MOVE " + p[0] + " " + p[1] + " " + c.last); }
        c.send_mouse_press(4);  w.println("PRESS 4 " + c.last);
        c.send_mouse_press(1);  w.println("PRESS 1 " + c.last);
        c.send_mouse_press(2);  w.println("PRESS 2 " + c.last);
        c.send_mouse_release(4);w.println("RELEASE 4 " + c.last);
        c.mouse_mode_change(true);  w.println("SELECTABS " + c.last);
        c.mouse_mode_change(false); w.println("SELECTREL " + c.last);
        c.send_ctrl_alt_del();  w.println("CAD " + c.last);

        // Keyboard: printable ASCII via the locale translator (en_US identity).
        LocaleTranslator lt = new LocaleTranslator();
        lt.selectLocale("en_US");
        for (int ch = 0x20; ch <= 0x7e; ch++)
            w.println("KEYT " + ch + " " + hex(lt.translate((char) ch)));

        // Enter / Backspace via translate_key (KEY_TYPED path).
        w.println("KEYR 13 " + hex(c.translate_key(typed(src, '\r'))));
        w.println("KEYR 8 "  + hex(c.translate_key(typed(src, '\b'))));

        // Tab / Esc / arrows via translate_special_key (KEY_PRESSED path).
        w.println("KEYS 9 "  + hex(c.translate_special_key(pressed(src, 9))));
        w.println("KEYS 27 " + hex(c.translate_special_key(pressed(src, 27))));
        w.println("KEYS 38 " + hex(c.translate_special_key(pressed(src, 38))));
        w.println("KEYS 40 " + hex(c.translate_special_key(pressed(src, 40))));
        w.println("KEYS 37 " + hex(c.translate_special_key(pressed(src, 37))));
        w.println("KEYS 39 " + hex(c.translate_special_key(pressed(src, 39))));
        w.close();
        System.out.println("wrote build/input_java.txt");
        System.exit(0);
    }

    static KeyEvent typed(Component src, char ch) {
        return new KeyEvent(src, KeyEvent.KEY_TYPED, 0L, 0, KeyEvent.VK_UNDEFINED, ch);
    }
    static KeyEvent pressed(Component src, int keyCode) {
        return new KeyEvent(src, KeyEvent.KEY_PRESSED, 0L, 0, keyCode, KeyEvent.CHAR_UNDEFINED);
    }
}
