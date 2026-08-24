// DvcCacheProbe.java — reference oracle for dvc_cache.hpp.
//
// Same package as cim, so it calls the package-private cache_reset/lru/find/
// prune directly; reads the private-static dvc_cc_* / dvc_pixcode / next_1 state
// via reflection. Also dumps HP's actual color_remap_table (built by invoking
// process_dvc once with the FSM inhibited, so no bytes are decoded and no GUI
// is touched).
//
//   javac -cp rc175p10.jar -d build cpp/DvcCacheProbe.java
//   java  -cp "rc175p10.jar;build" com.hp.ilo2.remcons.DvcCacheProbe
package com.hp.ilo2.remcons;

import java.io.PrintWriter;
import java.lang.reflect.Field;

public class DvcCacheProbe {
    static Field f(String n) throws Exception { Field x = cim.class.getDeclaredField(n); x.setAccessible(true); return x; }

    static final char[] OPT = {
        'R',
        'L','L','L','L','L','L',
        'F','F','L','P','L','F','P',
        'R',
        'L','L','L','L','L','L','L','L','L','L','L','L','L','L','L','L','L',
        'L',
        'F','F','P'
    };
    static final int[] OPA = {
        0,
        0x100,0x200,0x300,0x200,0x400,0x500,
        0,2,0x100,0,0x600,1,0,
        0,
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
        0x99,
        16,0,0
    };

    static String join(int[] a, int n) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++) { if (i > 0) s.append(','); s.append(a[i]); }
        return s.toString();
    }

    public static void main(String[] args) throws Exception {
        cim c = new cim();

        Field fActive = f("dvc_cc_active"), fColor = f("dvc_cc_color"),
              fUsage = f("dvc_cc_usage"),  fBlock = f("dvc_cc_block"),
              fPix = f("dvc_pixcode"),     fNext1 = f("next_1"),
              fInhibit = f("dvc_process_inhibit"), fRev = f("dvc_reversal");

        // Build HP's real color_remap_table: inhibit the FSM, force the one-time
        // init (guarded by dvc_reversal[255]==0), call process_dvc once.
        fInhibit.setBoolean(null, true);
        ((int[]) fRev.get(null))[255] = 0;
        c.process_dvc((char) 0);
        int[] remap = c.color_remap_table;
        PrintWriter rw = new PrintWriter("build/remap_java.txt");
        for (int i = 0; i < 4096; i++) rw.print(remap[i] + (i == 4095 ? "\n" : " "));
        rw.close();

        // Clean slate for the cache trace.
        fPix.setInt(null, 38);
        ((int[]) fNext1.get(null))[31] = 35;

        PrintWriter w = new PrintWriter("build/cache_java.txt");
        for (int i = 0; i < OPT.length; i++) {
            char t = OPT[i]; int arg = OPA[i]; int ret = 0; String label;
            switch (t) {
                case 'R': c.cache_reset();         label = "R";      break;
                case 'L': ret = c.cache_lru(arg);  label = "L" + arg; break;
                case 'F': ret = c.cache_find(arg); label = "F" + arg; break;
                default:  c.cache_prune();          label = "P";      break;
            }
            int active = fActive.getInt(null);
            int[] col = (int[]) fColor.get(null), usg = (int[]) fUsage.get(null), blk = (int[]) fBlock.get(null);
            int pix = fPix.getInt(null), n31 = ((int[]) fNext1.get(null))[31];
            w.printf("%s a=%d pc=%d n31=%d ret=%d C=%s U=%s B=%s%n",
                     label, active, pix, n31, ret,
                     join(col, active), join(usg, active), join(blk, active));
        }
        w.close();
        System.out.println("wrote build/cache_java.txt and build/remap_java.txt");
        System.exit(0);
    }
}
