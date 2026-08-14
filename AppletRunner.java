
import java.applet.Applet;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;

public class AppletRunner extends Frame {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: AppletRunner <applet-class> [param=value ...]");
            return;
        }
        String className = args[0];
        final HashMap<String, String> params = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String[] kv = args[i].split("=", 2);
            if (kv.length == 2) params.put(kv[0], kv[1]);
        }

        Class<?> cls = Class.forName(className);
        final Applet applet = (Applet) cls.newInstance();

        applet.setStub(new java.applet.AppletStub() {
            public boolean isActive() { return true; }
            public java.net.URL getDocumentBase() {
                try { return new java.net.URL("https://10.10.123.129/"); }
                catch (Exception e) { return null; }
            }
            public java.net.URL getCodeBase() { return getDocumentBase(); }
            public String getParameter(String name) { return params.get(name); }
            public java.applet.AppletContext getAppletContext() { return null; }
            public void appletResize(int w, int h) {}
        });

        AppletRunner frame = new AppletRunner();
        frame.setTitle("iLO 2 Remote Console - 10.10.123.129");
        frame.setLayout(new BorderLayout());
        frame.add(applet, BorderLayout.CENTER);
        frame.setSize(1024, 768);
        frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                applet.stop();
                applet.destroy();
                System.exit(0);
            }
        });

        applet.init();
        applet.start();
        frame.setVisible(true);
    }
}
