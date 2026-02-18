#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# -----------------------------
# Helpers
# -----------------------------
def run_command(cmd: list[str]) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.stdout

def mac_oui(mac: str) -> str:
    mac = mac.strip().lower()
    parts = mac.split(":")
    return ":".join(parts[:3]).upper() if len(parts) >= 3 else ""

def escape_nmap_style(buf: bytes) -> str:
    out = []
    for b in buf:
        if b == 0x00: out.append(r"\0")
        elif b == 0x5c: out.append(r"\\")
        elif b == 0x22: out.append(r"\"")
        elif b == 0x0a: out.append(r"\n")
        elif b == 0x0d: out.append(r"\r")
        elif b == 0x09: out.append(r"\t")
        elif 32 <= b <= 126: out.append(chr(b))
        else: out.append(r"\x%02x" % b)
    return "".join(out)

def extract_scan_report_target(raw: str) -> str | None:
    m = re.search(r"^Nmap scan report for (.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_network_distance(raw: str) -> str | None:
    m = re.search(r"^Network Distance:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_service_info(raw: str) -> str | None:
    m = re.search(r"^Service Info:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_mac_line(raw: str) -> tuple[str | None, str | None]:
    # Ex: MAC Address: D8:1F:12:3A:66:4D (Tuya Smart)
    m = re.search(r"^MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s*\((.*?)\))?$", raw, re.MULTILINE)
    if not m:
        return None, None
    return m.group(1).upper(), (m.group(2).strip() if m.group(2) else None)

def extract_device_type(raw: str) -> str | None:
    m = re.search(r"^Device type:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_running(raw: str) -> str | None:
    m = re.search(r"^Running:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_os_details(raw: str) -> str | None:
    m = re.search(r"^OS details:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip() if m else None

def extract_ports(raw: str) -> list[str]:
    lines = raw.splitlines()
    out = []
    in_table = False
    for line in lines:
        if line.strip().startswith("PORT") and "STATE" in line and "SERVICE" in line:
            in_table = True
            continue
        if in_table:
            # tabela termina quando começa outra seção
            if line.strip() == "" or line.startswith("MAC Address:") or line.startswith("Device type:") or line.startswith("Running:") \
               or line.startswith("OS ") or line.startswith("Network Distance:") or line.startswith("Host script results:") \
               or line.startswith("OS and Service detection performed.") or line.startswith("Nmap done:") or line.startswith("No exact"):
                break

            if re.match(r"^\d+\/\w+\s+\w+\s+\S+", line.strip()):
                out.append(line.rstrip())
    return out

def is_iot_mode(raw: str) -> bool:
    run = extract_running(raw) or ""
    if "lwip" in run.lower():
        return True
    # heurística: tuya + porta 6668
    if re.search(r"^6668/tcp\s+open", raw, re.MULTILINE):
        if re.search(r"\bTuya\b|\btuya\b", raw):
            return True
    return False

# -----------------------------
# PC-mode: TCP/IP stable fields from OS:SCAN fingerprint
# -----------------------------
def extract_tcpip_stable_from_os_scan(raw: str) -> dict:
    stable = {}

    # P= dentro do OS:SCAN(...) (quando existir)
    m = re.search(r"OS:SCAN\([^\)]*%P=([^%)]*)", raw)
    if m:
        stable["P"] = m.group(1).strip()

    # juntar todas linhas OS:
    os_lines = []
    for line in raw.splitlines():
        if line.startswith("OS:"):
            os_lines.append(line[3:].strip())
    os_blob = "".join(os_lines)

    def grab(name: str):
        mm = re.search(rf"{name}\((.*?)\)", os_blob)
        return mm.group(1).strip() if mm else None

    for key in ["OPS", "WIN", "ECN", "U1", "IE"]:
        val = grab(key)
        if val:
            stable[key] = val

    return stable

# -----------------------------
# IoT-mode: optional SF block extraction (no hash)
# -----------------------------
def extract_sf_block(raw: str) -> dict | None:
    """
    Extracts one SF:(Probe,LenHex,"..."); block if present.
    Returns: {probe, len_hex, payload_escaped, prefix_escaped, suffix_escaped}
    """
    lines = raw.splitlines()
    sf_lines = []
    in_sf = False

    for line in lines:
        if line.startswith("SF:(") or line.startswith("SF-Port"):
            # SF-Port header is metadata; SF:(...) contains payload
            # start collecting when we see SF:(...
            if line.startswith("SF:("):
                in_sf = True
                sf_lines.append(line)
            continue

        if in_sf:
            if line.startswith("SF:"):
                sf_lines.append(line)
                # detect end
                if line.strip().endswith('");'):
                    break
            else:
                # stop if SF block ended
                break

    if not sf_lines:
        return None

    # join payload lines: remove leading "SF:" and newlines
    joined = "\n".join(sf_lines)
    joined = re.sub(r"^SF:", "", joined, flags=re.MULTILINE).strip()

    m = re.search(r'^\(([^,]+),([0-9A-Fa-f]+),\"(.*)\"\);\s*$', joined, re.S)
    if not m:
        return None

    probe = m.group(1).strip()
    len_hex = m.group(2).strip().upper()
    payload = m.group(3)

    # payload can contain embedded "\nSF:" remnants; remove if any
    payload = payload.replace("\nSF:", "").replace("\r", "")

    # For a stable text signature (no hash), keep prefix/suffix windows
    # Using escaped characters as captured (already \x.. etc.)
    prefix = payload[:160]            # ~a good stable window
    suffix = payload[-120:] if len(payload) > 120 else payload

    return {
        "probe": probe,
        "len_hex": len_hex,
        "prefix": prefix,
        "suffix": suffix,
    }

def extract_fingerprint_strings_probe(raw: str) -> str | None:
    """
    Captures which probe name appeared under fingerprint-strings (if present).
    Example:
    | fingerprint-strings:
    |   HTTPOptions:
    """
    m = re.search(r"^\|\s*fingerprint-strings:\s*$", raw, re.MULTILINE)
    if not m:
        return None
    # find next indented line like "|   HTTPOptions:"
    m2 = re.search(r"^\|\s{3}([A-Za-z0-9_-]+):\s*$", raw[m.end():], re.MULTILINE)
    return m2.group(1) if m2 else None

# -----------------------------
# Host scripts stable (keep whitelist)
# -----------------------------
def extract_host_scripts_stable(raw: str) -> list[str]:
    lines = raw.splitlines()
    out = []
    in_scripts = False
    keep_current = False

    whitelist = {"smb2-security-mode"}

    for line in lines:
        if line.strip() == "Host script results:":
            in_scripts = True
            continue
        if not in_scripts:
            continue
        if line.startswith("Nmap done:"):
            break

        m = re.match(r"^\|\s*([a-zA-Z0-9_-]+):\s*$", line)
        if m:
            script_name = m.group(1)
            keep_current = script_name in whitelist
            if keep_current:
                out.append(f"| {script_name}:")
            continue

        if keep_current:
            # drop any time-like fields
            if re.search(r"\bdate:\b", line, re.IGNORECASE):  # smb2-time etc.
                continue
            if re.search(r"\d{4}-\d{2}-\d{2}T", line):
                continue
            if line.startswith("|") or line.startswith("|_"):
                out.append(line.rstrip())

    return out

# -----------------------------
# Build NORM (PC or IoT)
# -----------------------------
def build_norm(raw: str) -> str:
    target = extract_scan_report_target(raw) or "<alvo>"
    ports = extract_ports(raw)
    dist = extract_network_distance(raw)
    svc = extract_service_info(raw)

    mac, mac_vendor = extract_mac_line(raw)
    dtype = extract_device_type(raw)
    running = extract_running(raw)
    osdet = extract_os_details(raw)

    out = []
    out.append(f"Nmap scan report for {target}")

    # PORTS
    out.append("PORT    STATE SERVICE         VERSION")
    out.extend(ports if ports else ["<sem portas detectadas>"])
    out.append("")

    if dist:
        out.append(f"Network Distance: {dist}")
    if svc:
        out.append(f"Service Info: {svc}")
    out.append("")

    # Decide mode
    if is_iot_mode(raw):
        out.append("IOT stable fields:")
        if mac:
            oui = mac_oui(mac)
            if mac_vendor:
                out.append(f"  mac={mac} ({mac_vendor})")
            else:
                out.append(f"  mac={mac}")
            if oui:
                out.append(f"  mac_oui={oui}")
        if dtype:
            out.append(f"  device_type={dtype}")
        if running:
            out.append(f"  running={running}")
        if osdet:
            out.append(f"  os_details={osdet}")

        # port/service guess (from port line)
        # try to pick line for 6668 if exists
        svc_guess = None
        for pl in ports:
            if pl.strip().startswith("6668/"):
                # columns: PORT STATE SERVICE VERSION...
                parts = pl.split()
                if len(parts) >= 3:
                    svc_guess = parts[2]
                break
        if svc_guess:
            out.append(f"  service_guess={svc_guess}")
        out.append("")

        # Optional: SF block
        fp_probe = extract_fingerprint_strings_probe(raw)
        sf = extract_sf_block(raw)
        if fp_probe or sf:
            out.append("Application probe (optional):")
            if fp_probe:
                out.append(f"  fingerprint_strings_probe={fp_probe}")
            if sf:
                out.append(f"  sf_probe={sf['probe']}")
                out.append(f"  sf_reply_len_hex={sf['len_hex']}")
                out.append(f"  sf_reply_prefix={sf['prefix']}")
                out.append(f"  sf_reply_suffix={sf['suffix']}")
            out.append("")
        else:
            out.append("Application probe (optional):")
            out.append("  <não capturado>")
            out.append("")
    else:
        # PC-mode TCP/IP stable fields from OS:SCAN
        tcpip = extract_tcpip_stable_from_os_scan(raw)
        out.append("TCP/IP fingerprint (stable fields):")
        if tcpip:
            if "P" in tcpip:
                out.append(f"  P={tcpip['P']}")
            for k in ["OPS", "WIN", "ECN", "U1", "IE"]:
                if k in tcpip:
                    out.append(f"  {k}({tcpip[k]})")
        else:
            out.append("  <não capturado>")
        out.append("")

        scripts = extract_host_scripts_stable(raw)
        if scripts:
            out.append("Host script results (stable):")
            out.extend(scripts)
            out.append("")

    return "\n".join(out).strip() + "\n"

# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) < 3:
        print("Uso:")
        print("  python3 nmap_snapshot_stable.py <pasta_saida> <ip> [args do nmap...]")
        print("Exemplo:")
        print("  python3 nmap_snapshot_stable.py snapshots 192.168.1.103 -T4 -sV -sC -O -Pn")
        sys.exit(1)

    out_dir = Path(sys.argv[1])
    ip = sys.argv[2]
    nmap_args = sys.argv[3:] or ["-T4", "-sV", "-sC", "-O", "-Pn"]

    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["nmap"] + nmap_args + [ip]
    raw = run_command(cmd)
    norm = build_norm(raw)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = out_dir / f"nmap_{ip}_{ts}.raw.txt"
    norm_path = out_dir / f"nmap_{ip}_{ts}.norm.txt"

    raw_path.write_text(raw, encoding="utf-8", errors="ignore")
    norm_path.write_text(norm, encoding="utf-8", errors="ignore")

    print(f"[OK] RAW  -> {raw_path}")
    print(f"[OK] NORM -> {norm_path}")

if __name__ == "__main__":
    main()
