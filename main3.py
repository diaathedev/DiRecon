#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tool For Web Apps Enumeration | for Web Pentesters / Bug Hunters
Developed By Diaa

Options:
  1) Subdomain Enumeration     (no nmap, no dirsearch)
  2) Directories Fuzzing       (dirsearch)
  3) Technologies Used         (httpx -td + whatweb)
  4) Collect Parameters        (arjun)
  5) Nmap Scan                 (file / single domain / manual list)
  6) FULL Scan                 (1 -> 3 -> 2 -> 4 -> 5)
  7) Install / Update Tools
  0) Exit
"""

import os
import sys
import shlex
import shutil
import subprocess
from pathlib import Path
from datetime import datetime


# ============ PATH setup (prepend ~/go/bin FIRST so Go tools win over pip) ===
GO_BIN = os.path.expanduser("~/go/bin")

def _setup_path():
    priority = [
        GO_BIN,
        os.path.expanduser("~/.local/bin"),
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/snap/bin",
    ]
    existing = [p for p in priority if os.path.isdir(p)]
    cur = os.environ.get("PATH", "").split(os.pathsep)
    for p in cur:
        if p and p not in existing:
            existing.append(p)
    os.environ["PATH"] = os.pathsep.join(existing)

_setup_path()


# ============ Colors ============
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


BANNER = r"""
░███████   ░██░█████████
░██   ░██     ░██     ░██
░██    ░██ ░██░██     ░██  ░███████   ░███████   ░███████  ░████████
░██    ░██ ░██░█████████  ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██
░██    ░██ ░██░██   ░██   ░█████████ ░██        ░██    ░██ ░██    ░██
░██   ░██  ░██░██    ░██  ░██        ░██    ░██ ░██    ░██ ░██    ░██
░███████   ░██░██     ░██  ░███████   ░███████   ░███████  ░██    ░██

#####################################################################################
#Tool For Web apps Enumration | for Web Pentesters/ bug hunters | Developed By Diaa #
#                                                                                   #
#####################################################################################
"""


# ============ Tools definitions ============
GO_TOOLS = {
    "subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "anew":        "github.com/tomnomnom/anew@latest",
    "httpx":       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "gospider":    "github.com/jaeles-project/gospider@latest",
    "subzy":       "github.com/PentestPad/subzy@latest",     # maintained fork
}
PIPX_TOOLS = ["dirsearch", "arjun"]
PIP_TOOLS  = ["smuggler"]
APT_TOOLS  = ["nmap", "whatweb"]

# Full tool list for verification
ALL_TOOLS = list(GO_TOOLS.keys()) + ["dirsearch", "arjun", "smuggler",
                                     "nmap", "whatweb"]


# ============ Tool locator (handles httpx / python collision) ============
def _is_pd_httpx(path):
    """True if 'httpx' is ProjectDiscovery's, not Python's."""
    try:
        out = subprocess.run([path, "-version"],
                             capture_output=True, text=True, timeout=5)
        return "projectdiscovery" in (out.stdout + out.stderr).lower()
    except Exception:
        return False


def find_tool(name):
    """Return real absolute path to a tool, or None.
    Prefers ~/go/bin for Go tools; skips Python's httpx for 'httpx'."""
    # Try ~/go/bin first
    cand = os.path.join(GO_BIN, name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        if name == "httpx" and not _is_pd_httpx(cand):
            pass  # weird, fall through
        else:
            return cand

    # httpx: only accept PD version
    if name == "httpx":
        w = shutil.which("httpx")
        if w and _is_pd_httpx(w):
            return w
        return None

    # smuggler installs as smuggler.py
    if name == "smuggler":
        for n in ("smuggler", "smuggler.py"):
            w = shutil.which(n)
            if w:
                return w
        return None

    return shutil.which(name)


# ============ Helpers ============
def log(msg, level="info"):
    colors = {"info": C.CYAN, "ok": C.GREEN, "warn": C.YELLOW,
              "err": C.RED, "step": C.MAGENTA}
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]",
              "err": "[-]", "step": "[>]"}
    print(f"{colors.get(level, C.RESET)}{prefix.get(level, '[*]')} {msg}{C.RESET}")


def run(cmd, out_file=None, append=False, check_tool=True, tool_name=None):
    """Run a shell command. Optionally tee output to file.
    If tool_name is given (or auto-detected as first word), it is resolved
    to its absolute path via find_tool() so the right binary is used."""
    if check_tool:
        tname = tool_name or cmd.split(maxsplit=1)[0]
        real = find_tool(tname)
        if not real:
            log(f"'{tname}' not found - skipping.", "warn")
            return False
        # substitute real path for the first token
        rest = cmd.split(maxsplit=1)[1] if " " in cmd else ""
        cmd = shlex.quote(real) + (" " + rest if rest else "")

    log(f"$ {cmd}", "step")
    try:
        if out_file:
            mode = "a" if append else "w"
            with open(out_file, mode) as f:
                proc = subprocess.Popen(cmd, shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        text=True)
                for line in proc.stdout:
                    sys.stdout.write(line)
                    f.write(line)
                proc.wait()
        else:
            subprocess.run(cmd, shell=True)
        return True
    except KeyboardInterrupt:
        raise
    except Exception as e:
        log(f"Command failed: {e}", "err")
        return False


def count_lines(path):
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def prompt(msg):
    try:
        return input(f"{C.BOLD}{msg}{C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def make_outdir(name):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = name.replace("://", "_").replace("/", "_").replace(".", "_")
    outdir = Path(f"output_{safe}_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def normalize_urls(src_file, dst_file):
    """Ensure every line is a URL (https:// by default). Returns dst_file."""
    seen = set()
    with open(src_file) as fin, open(dst_file, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            url = line if line.startswith(("http://", "https://")) else "https://" + line
            if url not in seen:
                seen.add(url)
                fout.write(url + "\n")
    return dst_file


# ============ Target input helper (new) ============
def gather_targets(outdir=None):
    """
    Ask the user how to provide targets for tech/dirs/params/nmap.
     1) Path to a file (one host/URL per line)
     2) Single domain (e.g. example.com)
     3) Multiple domains (comma-separated)
    Returns a path to a normalized file with URLs (or None).
    """
    print(f"""
{C.CYAN}1){C.RESET} Path to a file (one host/URL per line)
{C.CYAN}2){C.RESET} Single domain (e.g. example.com)
{C.CYAN}3){C.RESET} Multiple domains (comma-separated)
""")
    ch = prompt("> ")
    if not outdir:
        outdir = Path(f"output_targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    tmp = outdir / "targets.txt"
    normalized = outdir / "targets_urls.txt"

    if ch == "1":
        fp = prompt("Path to file: ").strip()
        if not os.path.isfile(fp):
            log("File not found.", "err")
            return None
        return normalize_urls(fp, normalized)

    if ch == "2":
        d = prompt("Domain: ").strip()
        if not d:
            return None
        tmp.write_text(d + "\n")
        return normalize_urls(tmp, normalized)

    if ch == "3":
        raw = prompt("Domains (comma-separated, e.g. google.com,youtube.com): ")
        hosts = [h.strip() for h in raw.split(",") if h.strip()]
        if not hosts:
            return None
        tmp.write_text("\n".join(hosts) + "\n")
        return normalize_urls(tmp, normalized)

    log("Invalid choice.", "err")
    return None


# ============ Menu ============
def print_menu():
    print(f"""
{C.GREEN}1){C.RESET} Subdomain Enumeration
{C.GREEN}2){C.RESET} Directories Fuzzing
{C.GREEN}3){C.RESET} Technologies Used
{C.GREEN}4){C.RESET} Collect Parameters (arjun)
{C.GREEN}5){C.RESET} Nmap Scan
{C.GREEN}6){C.RESET} {C.BOLD}FULL Scan (all of the above){C.RESET}
{C.GREEN}7){C.RESET} Install / Update Tools
{C.GREEN}8){C.RESET} Verify Tools
{C.GREEN}0){C.RESET} Exit
""")


# ================================================================
#  OPTION 7 / 8 - Install & Verify Tools
# ================================================================
def verify_tools():
    print()
    log("Tool status:", "info")
    ok, miss = 0, 0
    for t in ALL_TOOLS:
        real = find_tool(t)
        if real:
            log(f"  [ OK ] {t:12s} -> {real}", "ok")
            ok += 1
        else:
            log(f"  [MISS] {t:12s}", "warn")
            miss += 1
    log(f"{ok} installed, {miss} missing", "info")
    return miss == 0


def install_tools():
    log("=" * 60, "info")
    log("Install / Update Tools", "ok")
    log("=" * 60, "info")

    # ---- Go ----
    if shutil.which("go"):
        log("Go detected - installing Go tools...", "ok")
        for name, pkg in GO_TOOLS.items():
            if find_tool(name):
                log(f"{name} already installed", "ok")
                continue
            log(f"Installing {name} ...", "step")
            run(f"go install -v {pkg}", check_tool=False)
        _setup_path()
    else:
        log("Go is NOT installed - skipping Go tools.", "err")
        log("Install Go: https://go.dev/dl/  or  sudo apt install -y golang-go", "warn")

    # ---- pipx / pip ----
    for pkg in PIPX_TOOLS:
        if find_tool(pkg):
            log(f"{pkg} already installed", "ok")
            continue
        if shutil.which("pipx"):
            log(f"Installing {pkg} via pipx ...", "step")
            run(f"pipx install {pkg}", check_tool=False)
        else:
            log(f"Installing {pkg} via pip3 --user ...", "step")
            run(f"pip3 install --user {pkg}", check_tool=False)

    for pkg in PIP_TOOLS:
        if find_tool(pkg):
            log(f"{pkg} already installed", "ok")
            continue
        log(f"Installing {pkg} via pip3 --user ...", "step")
        run(f"pip3 install --user {pkg}", check_tool=False)

    # ---- apt ----
    missing_apt = [t for t in APT_TOOLS if not shutil.which(t)]
    if missing_apt:
        log(f"Installing system tools: {' '.join(missing_apt)}", "step")
        run(f"sudo apt-get update && sudo apt-get install -y {' '.join(missing_apt)}",
            check_tool=False)
    else:
        log("All apt tools already installed", "ok")

    _setup_path()
    print()
    log("Verifying installation...", "info")
    verify_tools()
    print()
    log("Done. If anything is still missing, re-run option 7.", "ok")


# ================================================================
#  OPTION 1 - Subdomain Enumeration  (NO nmap, NO dirsearch)
# ================================================================
def subdomain_enum(target=None, outdir=None, interactive=True):
    log("=" * 60, "info")
    log("Subdomain Enumeration", "ok")
    log("=" * 60, "info")

    if interactive and not target:
        target = prompt("Enter target domain (e.g. example.com): ")
    if not target:
        log("No target provided.", "err")
        return None
    target = target.replace("https://", "").replace("http://", "").strip("/")

    if outdir is None:
        outdir = make_outdir(target)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    log(f"Output directory: {outdir}", "info")

    raw_file    = outdir / "subdomains.txt"
    unique_file = outdir / "unique_subdomains.txt"
    httpx_file  = outdir / "httpx.txt"
    httpx200    = outdir / "httpx200.txt"
    allurls     = outdir / "allurls.txt"
    katana_f    = outdir / "katana.txt"
    gosp_dir    = outdir / "gospider_output"

    # 1. Collect
    log("[1/10] Collecting subdomains (subfinder/assetfinder/amass)...", "step")
    used = []
    if find_tool("subfinder"):
        run(f"subfinder -d {target} -silent -o {raw_file}")
        used.append("subfinder")
    if find_tool("assetfinder"):
        run(f"assetfinder --subs-only {target} >> {raw_file}")
        used.append("assetfinder")
    if find_tool("amass"):
        run(f"amass enum -passive -d {target} -o - >> {raw_file}")
        used.append("amass")
    if not used:
        log("No subdomain tools found. Run option 7.", "err")
        return None
    log(f"Used: {', '.join(used)}", "ok")

    # 2. Dedupe
    log("[2/10] Removing duplicate subdomains...", "step")
    if find_tool("anew"):
        run(f"cat {raw_file} | anew {unique_file} > /dev/null")
    else:
        run(f"sort -u {raw_file} -o {unique_file}")
    log(f"Unique subdomains: {count_lines(unique_file)}", "ok")

    # 3. Delete raw
    log("[3/10] Removing raw subdomains.txt ...", "step")
    try:
        raw_file.unlink(missing_ok=True)
    except Exception as e:
        log(f"Could not delete raw file: {e}", "warn")

    # 4. Subzy
    log("[4/10] Subdomain takeover check (subzy)...", "step")
    if find_tool("subzy") and count_lines(unique_file) > 0:
        run(f"subzy run --targets {unique_file} --vuln --hide_fails "
            f"| tee {outdir / 'subzy.txt'}")
    else:
        log("subzy missing or no subdomains.", "warn")

    # 5. httpx live
    log("[5/10] Probing live hosts (httpx)...", "step")
    if find_tool("httpx") and count_lines(unique_file) > 0:
        run(f"cat {unique_file} | httpx -silent -o {httpx_file}")
        log(f"Live hosts: {count_lines(httpx_file)}", "ok")
    else:
        log("httpx missing (ProjectDiscovery).", "warn")

    # 6. httpx 200
    log("[6/10] Filtering 200 OK hosts...", "step")
    if find_tool("httpx") and httpx_file.exists():
        run(f"cat {httpx_file} | httpx -silent -mc 200 -o {httpx200}")
        log(f"200 OK hosts: {count_lines(httpx200)}", "ok")

    # 7. Smuggler
    log("[7/10] HTTP request smuggling (smuggler)...", "step")
    if find_tool("smuggler") and httpx_file.exists():
        sm = find_tool("smuggler")
        run(f"cat {httpx_file} | {shlex.quote(sm)} | tee {outdir / 'smuggler.txt'}",
            check_tool=False)
    else:
        log("smuggler missing or no live hosts.", "warn")

    # 8. waybackurls
    log("[8/10] Gathering URLs (waybackurls)...", "step")
    if find_tool("waybackurls") and httpx200.exists():
        run(f"cat {httpx200} | waybackurls | sort -u | tee {allurls}")
    else:
        log("waybackurls missing or no 200 hosts.", "warn")

    # 9. Katana
    log("[9/10] Crawling with katana...", "step")
    if find_tool("katana") and httpx_file.exists():
        run(f"katana -list {httpx_file} -silent -o {katana_f}")
    else:
        log("katana missing or no live hosts.", "warn")

    # 10. Gospider
    log("[10/10] Crawling with gospider...", "step")
    if find_tool("gospider") and httpx_file.exists():
        run(f"gospider -S {httpx_file} -o {gosp_dir} --quiet")
    else:
        log("gospider missing or no live hosts.", "warn")

    print()
    log("=" * 60, "ok")
    log(f"Subdomain Enumeration finished for {target}", "ok")
    log(f"Results in: {outdir}", "ok")
    log("=" * 60, "ok")
    print(f"""
{C.BOLD}Summary:{C.RESET}
  {C.CYAN}unique subdomains :{C.RESET} {unique_file} ({count_lines(unique_file)})
  {C.CYAN}live hosts        :{C.RESET} {httpx_file}  ({count_lines(httpx_file)})
  {C.CYAN}200 OK hosts      :{C.RESET} {httpx200}    ({count_lines(httpx200)})
  {C.CYAN}all URLs          :{C.RESET} {allurls}     ({count_lines(allurls)})
  {C.CYAN}katana URLs       :{C.RESET} {katana_f}    ({count_lines(katana_f)})
""")

    return {
        "target": target,
        "outdir": outdir,
        "unique": unique_file,
        "httpx": httpx_file,
        "httpx200": httpx200,
    }


# ================================================================
#  OPTION 2 - Directories Fuzzing (dirsearch)
# ================================================================
def dir_fuzzing(targets_file=None, outdir=None, interactive=True):
    log("=" * 60, "info")
    log("Directories Fuzzing (dirsearch)", "ok")
    log("=" * 60, "info")

    if not find_tool("dirsearch"):
        log("dirsearch not installed. Run option 7.", "err")
        return None

    if interactive and not targets_file:
        if outdir is None:
            outdir = Path(f"output_dirs_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        targets_file = gather_targets(outdir=outdir)
    if not targets_file or not os.path.isfile(str(targets_file)):
        log("No valid targets.", "err")
        return None

    if outdir is None:
        outdir = Path(targets_file).parent
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    ext = ("conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,"
           "py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,"
           "jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,"
           "sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,"
           "log,xml")

    out = outdir / "dirsearch.txt"
    run(f"dirsearch -l {targets_file} -o {out} -i 200 -e {ext}")
    log(f"dirsearch results -> {out}", "ok")
    return out


# ================================================================
#  OPTION 3 - Technologies Used
# ================================================================
def tech_detect(targets_file=None, outdir=None, interactive=True):
    log("=" * 60, "info")
    log("Technologies Detection", "ok")
    log("=" * 60, "info")

    if interactive and not targets_file:
        if outdir is None:
            outdir = Path(f"output_tech_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        targets_file = gather_targets(outdir=outdir)
    if not targets_file or not os.path.isfile(str(targets_file)):
        log("No valid targets.", "err")
        return None

    if outdir is None:
        outdir = Path(targets_file).parent
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    tech_out = outdir / "technologies.txt"

    if find_tool("httpx"):
        log("Running httpx -td ...", "step")
        run(f"cat {targets_file} | httpx -silent -td | tee {tech_out}")
        log(f"Tech results -> {tech_out}", "ok")
    else:
        log("httpx (ProjectDiscovery) missing.", "warn")

    if find_tool("whatweb"):
        log("Running whatweb ...", "step")
        ww_out = outdir / "whatweb.txt"
        run(f"whatweb --input-file={targets_file} "
            f"--log-brief={ww_out} --no-errors")
        log(f"whatweb results -> {ww_out}", "ok")
    else:
        log("whatweb missing (optional).", "warn")

    return tech_out


# ================================================================
#  OPTION 4 - Collect Parameters (arjun)
# ================================================================
def collect_params(targets_file=None, outdir=None, interactive=True):
    log("=" * 60, "info")
    log("Collect Parameters (arjun)", "ok")
    log("=" * 60, "info")

    if not find_tool("arjun"):
        log("arjun not installed. Run option 7.", "err")
        return None

    if interactive and not targets_file:
        if outdir is None:
            outdir = Path(f"output_params_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        targets_file = gather_targets(outdir=outdir)
    if not targets_file or not os.path.isfile(str(targets_file)):
        log("No valid targets.", "err")
        return None

    if outdir is None:
        outdir = Path(targets_file).parent
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    out = outdir / "arjun.txt"
    log("Running arjun (this can take a while)...", "step")
    run(f"arjun -i {targets_file} -oT {out} --stable")
    log(f"arjun results -> {out}", "ok")
    return out


# ================================================================
#  OPTION 5 - Nmap Scan (file / single domain / manual list)
# ================================================================
def nmap_scan(targets=None, outdir=None, interactive=True):
    log("=" * 60, "info")
    log("Nmap Scan", "ok")
    log("=" * 60, "info")

    if not find_tool("nmap"):
        log("nmap not installed. Run option 7.", "err")
        return None

    if outdir is None:
        outdir = Path(f"output_nmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    targets_file = outdir / "nmap_targets.txt"
    nmap_out     = outdir / "nmap.txt"
    nmap_xml     = outdir / "nmap.xml"

    # Decide targets
    if isinstance(targets, (str, Path)) and os.path.isfile(str(targets)):
        shutil.copy(str(targets), targets_file)
        log(f"Loaded targets from {targets}", "ok")
    elif isinstance(targets, list) and targets:
        targets_file.write_text("\n".join(targets) + "\n")
        log(f"Loaded {len(targets)} target(s)", "ok")
    elif interactive:
        tf = gather_targets(outdir=outdir)
        if not tf:
            return None
        shutil.copy(tf, targets_file)
    else:
        log("No targets for nmap.", "warn")
        return None

    if count_lines(targets_file) == 0:
        log("Empty target list.", "err")
        return None

    # Nmap needs bare hostnames/IPs, not URLs
    clean = outdir / "nmap_targets_clean.txt"
    with open(targets_file) as fin, open(clean, "w") as fout:
        for line in fin:
            h = line.strip()
            if not h:
                continue
            h = h.replace("https://", "").replace("http://", "").split("/")[0]
            fout.write(h + "\n")

    log(f"Scanning {count_lines(clean)} host(s) with nmap ...", "step")
    run(f"nmap -iL {clean} --top-ports 1000 -sV -T4 "
        f"-oN {nmap_out} -oX {nmap_xml}")
    log(f"nmap results -> {nmap_out}", "ok")
    return nmap_out


# ================================================================
#  OPTION 6 - FULL Scan
# ================================================================
def full_scan():
    log("=" * 60, "ok")
    log("FULL SCAN - running every module", "ok")
    log("=" * 60, "ok")

    target = prompt("Enter target domain (e.g. example.com): ")
    if not target:
        log("No target.", "err")
        return
    target = target.replace("https://", "").replace("http://", "").strip("/")

    outdir = make_outdir(f"full_{target}")
    log(f"All results will go into: {outdir}", "info")

    # 1) Subdomain enumeration
    res = subdomain_enum(target=target, outdir=outdir, interactive=False)
    if not res:
        log("Subdomain enumeration failed. Aborting full scan.", "err")
        return

    httpx_file  = res["httpx"]
    unique_file = res["unique"]

    # 3) Tech  2) Dirs  4) Params   (only if we have live hosts)
    if httpx_file.exists() and count_lines(httpx_file) > 0:
        tech_detect(targets_file=httpx_file,  outdir=outdir, interactive=False)
        dir_fuzzing(targets_file=httpx_file,  outdir=outdir, interactive=False)
        collect_params(targets_file=httpx_file, outdir=outdir, interactive=False)
    else:
        log("No live hosts -> skipping tech/dirs/params.", "warn")

    # 5) Nmap (last) on unique subdomains
    if unique_file.exists() and count_lines(unique_file) > 0:
        nmap_scan(targets=unique_file, outdir=outdir, interactive=False)
    else:
        log("No subdomains -> skipping nmap.", "warn")

    log("=" * 60, "ok")
    log(f"FULL SCAN COMPLETE.  Results in: {outdir}", "ok")
    log("=" * 60, "ok")


# ================================================================
#  MAIN
# ================================================================
def main():
    print(C.CYAN + BANNER + C.RESET)
    while True:
        print_menu()
        ch = prompt("> ")
        if ch == "1":
            subdomain_enum()
        elif ch == "2":
            dir_fuzzing()
        elif ch == "3":
            tech_detect()
        elif ch == "4":
            collect_params()
        elif ch == "5":
            nmap_scan()
        elif ch == "6":
            full_scan()
        elif ch == "7":
            install_tools()
        elif ch == "8":
            verify_tools()
        elif ch == "0":
            log("Bye!", "ok")
            sys.exit(0)
        else:
            log("Invalid choice.", "err")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("Interrupted. Exiting.", "warn")
        sys.exit(0)
