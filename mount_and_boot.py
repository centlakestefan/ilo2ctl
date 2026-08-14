#!/usr/bin/env python
"""
iLO 2 Virtual Media Mount + Boot script
Mounts a Windows ISO via HTTP URL, sets one-time boot to CD, and reboots.
"""
import os
import ssl
import sys
import hpilo

ILO_HOST = os.environ.get("ILO_HOST", "10.10.123.129")
ILO_USER = os.environ.get("ILO_USER", "Administrator")
ILO_PASS = os.environ.get("ILO_PASS")
if not ILO_PASS:
    sys.exit("Set the ILO_PASS environment variable to the iLO password.")

def get_ilo():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    ctx.options |= 0x4
    return hpilo.Ilo(ILO_HOST, login=ILO_USER, password=ILO_PASS, timeout=120, ssl_context=ctx)

def status():
    ilo = get_ilo()
    print("=== Server Power ===")
    print(f"  Power: {ilo.get_host_power_status()}")
    print("\n=== Virtual Media ===")
    vm = ilo.get_vm_status()
    for k, v in vm.items():
        print(f"  {k}: {v}")
    print("\n=== Boot Order ===")
    for i, item in enumerate(ilo.get_persistent_boot()):
        print(f"  {i+1}. {item}")

def mount(iso_url):
    ilo = get_ilo()
    print(f"[*] Mounting ISO: {iso_url}")

    # Insert virtual media
    print("[*] Inserting virtual CD...")
    ilo.insert_virtual_media(device='cdrom', image_url=iso_url)
    print("[+] ISO inserted")

    # Set VM boot option
    print("[*] Setting virtual media boot option...")
    ilo.set_vm_status(device='cdrom', boot_option='boot_once', write_protect=True)
    print("[+] Boot option set to boot_once")

    # Set one-time boot to CD
    print("[*] Setting one-time boot to CD-ROM...")
    ilo.set_one_time_boot('cdrom')
    print("[+] One-time boot set")

    # Verify
    print("\n=== Virtual Media Status ===")
    vm = ilo.get_vm_status()
    for k, v in vm.items():
        print(f"  {k}: {v}")

def reboot():
    ilo = get_ilo()
    power = ilo.get_host_power_status()
    print(f"[*] Current power state: {power}")

    if power == "ON":
        print("[*] Performing warm boot (reset)...")
        ilo.warm_boot_server()
        print("[+] Server is rebooting. It will boot from the virtual CD.")
    else:
        print("[*] Server is OFF. Powering on...")
        ilo.press_pwr_btn()
        print("[+] Power button pressed. Server will boot from the virtual CD.")

def eject():
    ilo = get_ilo()
    print("[*] Ejecting virtual media...")
    ilo.eject_virtual_media(device='cdrom')
    print("[+] Virtual CD ejected")

def usage():
    print(f"""
Usage: python {sys.argv[0]} <command> [args]

Commands:
  status              Show power, virtual media, and boot status
  mount <iso_url>     Mount ISO from HTTP URL and set one-time CD boot
  reboot              Reboot/power on the server
  eject               Eject virtual CD
  full <iso_url>      Mount + reboot in one step

Example:
  python {sys.argv[0]} full http://10.10.123.50:8080/win2022.iso
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "status":
        status()
    elif cmd == "mount" and len(sys.argv) >= 3:
        mount(sys.argv[2])
    elif cmd == "reboot":
        reboot()
    elif cmd == "eject":
        eject()
    elif cmd == "full" and len(sys.argv) >= 3:
        mount(sys.argv[2])
        print()
        reboot()
    else:
        usage()
        sys.exit(1)
