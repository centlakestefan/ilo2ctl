// DvcDecoderProbe.java — reference oracle for dvc_decoder.hpp.
//
// Drives the REAL com.hp.ilo2.remcons.cim FSM: replays build/decoder_stream.bin
// through cim.process_dvc byte-by-byte and snapshots cim's decoder state (via
// reflection into the private-static dvc_* fields) after each byte, plus the
// paste/dimension/text events (captured by a recording dvcwin subclass). Output
// must match the C++ decoder's snapshot byte-for-byte.
//
//   javac -cp rc175p10.jar -d build cpp/DvcDecoderProbe.java
//   java  -cp "rc175p10.jar;build" com.hp.ilo2.remcons.DvcDecoderProbe
package com.hp.ilo2.remcons;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;

public class DvcDecoderProbe {

    // Records the RecScreen events cim emits, without touching AWT.
    static final StringBuilder EVENTS = new StringBuilder();
    static int pastes = 0, dims = 0, texts = 0;

    static class RecScreen extends dvcwin {
        RecScreen() { super(1600, 1200); }
        public void paste_array(int[] b, int x, int y, int len) {
            EVENTS.append("P ").append(x).append(' ').append(y).append(' ').append(len).append(';'); pastes++;
        }
        public void set_abs_dimensions(int w, int h) {
            EVENTS.append("D ").append(w).append(' ').append(h).append(';'); dims++;
        }
        public void show_text(String s) { EVENTS.append("T ").append(s).append(';'); texts++; }
        public void set_framerate(int n) { /* no-op */ }
        public boolean repaint_it(int n) { return false; }
        public void start_updates() {} public void stop_updates() {}
    }

    static class RecCim extends cim {
        RecCim() { super(); this.screen = new RecScreen(); }
        // Prevent random bytes (firmware cmd 7) from actually launching mstsc.
        public void startRdp() {}
        public void stop_rdp() {}
    }

    static Field f(String n) throws Exception { Field x = cim.class.getDeclaredField(n); x.setAccessible(true); return x; }

    static byte[] readAll(String p) throws Exception {
        FileInputStream in = new FileInputStream(p);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        byte[] stream = readAll("build/decoder_stream.bin");

        RecCim c = new RecCim();
        byte[] dummy = new byte[16];
        c.setup_encryption(dummy, 0);   // so firmware cmd 9 (change_key) doesn't NPE
        c.setup_decryption(dummy);

        Field fState=f("dvc_decoder_state"), fNext=f("dvc_next_state"), fPix=f("dvc_pixel_count"),
              fLx=f("dvc_lastx"), fLy=f("dvc_lasty"), fNx=f("dvc_newx"), fNy=f("dvc_newy"),
              fSx=f("dvc_size_x"), fSy=f("dvc_size_y"), fYc=f("dvc_y_clipped"),
              fActive=f("dvc_cc_active"), fBcnt=f("dvc_ib_bcnt"), fZero=f("dvc_zero_count"),
              fCount=f("count_bytes"), fVid=f("video_detected"), fFr=f("framerate"),
              fScrX=f("screen_x"), fScrY=f("screen_y"), fFatal=f("fatal_count"),
              fCmdLast=f("cmd_last"), fCmdCnt=f("cmd_p_count"), fPchan=f("printchan"),
              fTimeout=f("timeout_count"), fNext1=f("next_1");

        PrintWriter w = new PrintWriter("build/decoder_java.txt");
        int[] next1 = (int[]) fNext1.get(null);
        for (int i = 0; i < stream.length; i++) {
            c.process_dvc((char) (stream[i] & 0xff));
            w.print(fState.getInt(null)); w.print(' ');
            w.print(fNext.getInt(null)); w.print(' ');
            w.print(fPix.getInt(null)); w.print(' ');
            w.print(fLx.getInt(null)); w.print(' ');
            w.print(fLy.getInt(null)); w.print(' ');
            w.print(fNx.getInt(null)); w.print(' ');
            w.print(fNy.getInt(null)); w.print(' ');
            w.print(fSx.getInt(null)); w.print(' ');
            w.print(fSy.getInt(null)); w.print(' ');
            w.print(fYc.getInt(null)); w.print(' ');
            w.print(fActive.getInt(null)); w.print(' ');
            w.print(fBcnt.getInt(null)); w.print(' ');
            w.print(fZero.getInt(null)); w.print(' ');
            w.print(fCount.getLong(null)); w.print(' ');
            w.print(((Boolean) fVid.get(null)) ? 1 : 0); w.print(' ');
            w.print(fFr.getInt(null)); w.print(' ');
            w.print(fScrX.getInt(c)); w.print(' ');
            w.print(fScrY.getInt(c)); w.print(' ');
            w.print(fFatal.getInt(null)); w.print(' ');
            w.print(fCmdLast.getInt(null)); w.print(' ');
            w.print(fCmdCnt.getInt(null)); w.print(' ');
            w.print(fPchan.getInt(null)); w.print(' ');
            w.print(fTimeout.getLong(null)); w.print(' ');
            w.print(next1[31]); w.print(' ');
            w.print(pastes); w.print(' ');
            w.print(dims); w.print(' ');
            w.print(texts); w.print('\n');
        }
        w.close();

        PrintWriter ew = new PrintWriter("build/decoder_events_java.txt");
        ew.print(EVENTS.toString());
        ew.close();

        System.out.println("fed " + stream.length + " bytes; pastes=" + pastes + " dims=" + dims + " texts=" + texts);
        System.exit(0);
    }
}
