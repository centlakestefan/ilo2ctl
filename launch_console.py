#!/usr/bin/env python
"""
iLO 2 Remote Console Launcher for HP ProLiant DL380 G6
Fetches session tokens from iLO 2, downloads the Java applet, and launches it.
"""
import ssl
import subprocess
import sys
import os
import re
import urllib.request

ILO_HOST = os.environ.get("ILO_HOST", "10.10.123.129")
ILO_USER = os.environ.get("ILO_USER", "Administrator")
ILO_PASS = os.environ.get("ILO_PASS")
if not ILO_PASS:
    sys.exit("Set the ILO_PASS environment variable to the iLO password.")
JAVA8 = r"C:\tools\jre8\jdk8u482-b08-jre\bin\java.exe"
JAR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rc175p10.jar")

def get_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    ctx.options |= 0x4  # allow legacy renegotiation
    return ctx

def fetch_page(url, cookie=None):
    """Fetch page using curl which handles iLO 2's old TLS correctly."""
    cmd = ["curl", "-k", "--tlsv1.0", "--tls-max", "1.0", "-s", url]
    if cookie:
        cmd += ["-b", cookie]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.stdout

def download_jar(cookie):
    if os.path.exists(JAR_PATH) and os.path.getsize(JAR_PATH) > 10000:
        print(f"[+] JAR already exists: {JAR_PATH}")
        return
    cmd = ["curl", "-k", "--tlsv1.0", "--tls-max", "1.0", "-s",
           "-b", cookie, "-o", JAR_PATH,
           f"https://{ILO_HOST}/rc175p10.jar"]
    subprocess.run(cmd, timeout=300)
    size = os.path.getsize(JAR_PATH)
    print(f"[+] Downloaded JAR: {size} bytes")

def main():
    import base64
    print("[*] Fetching login session from iLO 2...")
    login_page = fetch_page(f"https://{ILO_HOST}/login.htm")

    m = re.search(r'sessionkey="([^"]+)"', login_page)
    session_key = m.group(1) if m else None
    m = re.search(r'sessionindex="([^"]+)"', login_page)
    session_index = m.group(1) if m else None

    if not session_key or session_key == "NONEAVAILABLE":
        print("[!] No sessions available on iLO. Wait a few minutes and retry.")
        sys.exit(1)

    user_b64 = base64.b64encode(ILO_USER.encode()).decode()
    pass_b64 = base64.b64encode(ILO_PASS.encode()).decode()
    token = f"{session_index}:{user_b64}:{pass_b64}:{session_key}"
    cookie = f"hp-iLO-Login={token}"
    print(f"[+] Got session: {session_index}")

    print("[*] Downloading Java applet JAR...")
    download_jar(cookie)

    print("[*] Fetching remote console session parameters...")
    rc_page = fetch_page(f"https://{ILO_HOST}/drc2fram.htm", cookie)

    # Extract all info parameters
    params = {}
    for m in re.finditer(r'(info[0-9a-z]+)="([^"]*)"', rc_page):
        params[m.group(1)] = m.group(2)

    # Also extract infom, infomm, infok etc (numeric without quotes)
    for m in re.finditer(r'(info[a-z]+)=(\d+);', rc_page):
        if m.group(1) not in params:
            params[m.group(1)] = m.group(2)

    print(f"[+] Got {len(params)} console parameters")
    for k, v in sorted(params.items()):
        print(f"    {k} = {v}")

    # Build the appletviewer HTML or launch directly
    # The applet needs these params: INFO0-8, INFOA-D, INFOM, INFOMM, INFON, INFOO
    # We'll create a minimal HTML file and use appletviewer

    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "console.html")
    jar_abs = os.path.abspath(JAR_PATH).replace("\\", "/")

    param_tags = ""
    param_map = {
        "INFO0": params.get("info0", ""),
        "INFO1": params.get("info1", ""),
        "INFO3": params.get("info3", ""),
        "INFO6": params.get("info6", "23"),
        "INFO7": str(params.get("info7", "30")),
        "INFO8": params.get("info8", "1"),
        "INFOA": params.get("infoa", "1"),
        "INFOB": params.get("infob", ""),
        "INFOC": params.get("infoc", ""),
        "INFOD": params.get("infod", ""),
        "INFOM": params.get("infom", "1"),
        "INFOMM": params.get("infomm", "2"),
        "INFON": params.get("infon", "0"),
        "INFOO": params.get("infoo", "3389"),
    }

    for name, value in param_map.items():
        param_tags += f'    <PARAM NAME="{name}" VALUE="{value}">\n'

    html = f"""<html><body>
<applet
    code="com.hp.ilo2.remcons.remcons.class"
    archive="file:///{jar_abs}"
    width="1024" height="768">
{param_tags}</applet>
</body></html>
"""
    with open(html_path, 'w') as f:
        f.write(html)
    print(f"[+] Wrote {html_path}")

    # Launch with appletviewer (included in JDK 8, but not JRE)
    # Alternative: launch with java -cp using a wrapper
    # Let's try appletviewer first, fall back to direct class loading

    # Check if appletviewer exists in the JRE/JDK path
    java_dir = os.path.dirname(JAVA8)
    appletviewer = os.path.join(java_dir, "appletviewer.exe")

    if os.path.exists(appletviewer):
        print(f"[*] Launching with appletviewer...")
        cmd = [appletviewer, html_path]
    else:
        # Use java with a custom wrapper class
        print("[*] appletviewer not found in JRE, creating standalone wrapper...")
        wrapper_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "AppletRunner.java")
        wrapper_code = '''
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
                try { return new java.net.URL("https://''' + ILO_HOST + '''/"); }
                catch (Exception e) { return null; }
            }
            public java.net.URL getCodeBase() { return getDocumentBase(); }
            public String getParameter(String name) { return params.get(name); }
            public java.applet.AppletContext getAppletContext() { return null; }
            public void appletResize(int w, int h) {}
        });

        AppletRunner frame = new AppletRunner();
        frame.setTitle("iLO 2 Remote Console - ''' + ILO_HOST + '''");
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
'''
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_code)

        # Compile with JRE's tools... JRE doesn't have javac.
        # We'll need to compile with the JDK 17 but target Java 8
        javac = "javac"  # system javac (JDK 17)
        print("[*] Compiling AppletRunner with system javac (targeting Java 8)...")
        compile_result = subprocess.run(
            [javac, "-source", "1.8", "-target", "1.8",
             "-cp", JAR_PATH, "-d", os.path.dirname(wrapper_path),
             wrapper_path],
            capture_output=True, text=True
        )
        if compile_result.returncode != 0:
            print(f"[!] Compile failed: {compile_result.stderr}")
            # Try without source/target
            compile_result = subprocess.run(
                [javac, "-cp", JAR_PATH, "-d", os.path.dirname(wrapper_path),
                 wrapper_path],
                capture_output=True, text=True
            )
            if compile_result.returncode != 0:
                print(f"[!] Compile failed again: {compile_result.stderr}")
                sys.exit(1)

        print("[+] Compiled successfully")

        # Build command line with params
        param_args = [f"{k}={v}" for k, v in param_map.items()]
        cmd = [
            JAVA8, "-cp",
            f"{os.path.dirname(wrapper_path)};{JAR_PATH}",
            "AppletRunner",
            "com.hp.ilo2.remcons.remcons"
        ] + param_args

    print(f"[*] Launching remote console...")
    print(f"    Command: {' '.join(cmd[:5])}...")
    subprocess.Popen(cmd)
    print("[+] Console launched! Window should appear shortly.")
    print("[+] Note: The console connects to iLO via port 23 (telnet/KVM)")

if __name__ == "__main__":
    main()
