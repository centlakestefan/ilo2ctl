// DvcBitsProbe.java — reference oracle for dvc_bits.hpp.
//
// Reflects into the REAL com.hp.ilo2.remcons.cim to exercise its package-private
// init_reversal()/add_bits(char)/get_bits(int) and read its private-static
// dvc_* fields, so the C++ port can be diffed against HP's actual bit reader.
//
// Not part of the test suite and not needed to build or run it: the
// values this produced are frozen in tests/oracle/. Rebuilding them
// needs a copy of HP's rc175p10.jar you obtain yourself -- see
// tests/oracle/README.md for the compile-and-run recipe.
package com.hp.ilo2.remcons;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class DvcBitsProbe {
    static Field f(String name) throws Exception {
        Field fld = cim.class.getDeclaredField(name);
        fld.setAccessible(true);
        return fld;
    }
    static Method m(String name, Class<?>... args) throws Exception {
        Method mtd = cim.class.getDeclaredMethod(name, args);
        mtd.setAccessible(true);
        return mtd;
    }

    public static void main(String[] args) throws Exception {
        cim c = new cim();  // instance to invoke instance methods on

        Method mInit = m("init_reversal");
        Method mAdd  = m("add_bits", char.class);
        Method mGet  = m("get_bits", int.class);

        Field fAcc  = f("dvc_ib_acc"),  fBcnt = f("dvc_ib_bcnt"), fZero = f("dvc_zero_count");
        Field fCode = f("dvc_code"),    fState = f("dvc_decoder_state"), fNext = f("dvc_next_state");
        Field fRev  = f("dvc_reversal"), fLeft = f("dvc_left"), fRight = f("dvc_right");

        mInit.invoke(c);

        int[] rev = (int[]) fRev.get(null);
        int[] left = (int[]) fLeft.get(null);
        int[] right = (int[]) fRight.get(null);
        PrintWriter w = new PrintWriter("build/dvc_tables_java.txt");
        for (int i = 0; i < 256; i++) w.print(rev[i]   + (i == 255 ? "\n" : " "));
        for (int i = 0; i < 256; i++) w.print(left[i]  + (i == 255 ? "\n" : " "));
        for (int i = 0; i < 256; i++) w.print(right[i] + (i == 255 ? "\n" : " "));
        w.close();

        // get_bits read sequence
        fAcc.setInt(null, 0); fBcnt.setInt(null, 0); fZero.setInt(null, 0); fState.setInt(null, 1);
        mAdd.invoke(c, (char) 0xB3); mAdd.invoke(c, (char) 0x4D); mAdd.invoke(c, (char) 0xF0);
        int[] widths = {1, 2, 3, 4, 1, 5, 8};
        StringBuilder sb = new StringBuilder("java_reads");
        for (int wd : widths) { mGet.invoke(c, wd); sb.append(" ").append(fCode.getInt(null)); }
        System.out.println(sb.toString());

        // zero-run reset
        fAcc.setInt(null, 0); fBcnt.setInt(null, 0); fZero.setInt(null, 0);
        fState.setInt(null, 1); fNext.setInt(null, 1);
        int[] stream = {0x81, 0x00, 0x00, 0x00, 0x00};
        StringBuilder sb2 = new StringBuilder("java_zeros");
        for (int b : stream) {
            int r = (Integer) mAdd.invoke(c, (char) b);
            sb2.append(" r=").append(r).append("/zc=").append(fZero.getInt(null));
        }
        System.out.println(sb2.toString());
        System.exit(0);
    }
}
