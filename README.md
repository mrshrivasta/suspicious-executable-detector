# Suspicious Executable Detector

## Introduction

**Suspicious Executable Detector** is a single-file, read-only cybersecurity CLI + web-app tool, part of a 27-tool
suite built to simulate and perform real host, network and file forensics workflows — the kind a
security analyst runs day to day. Static triage of executables on one host. Parses ELF, PE and Mach-O headers, measures entropy, extracts strings and checks filesystem context, then orders what it found by how much it deserves a human's attention. Single Python file, a CLI and a 5-page web app, SQLite storage, SVG analytics, and a reviewed-file baseline.

👨‍💻 **Built by Karanam Shrivasta**
💡 Cyber Security | DFIR Enthusiast | Future Ethical Hacker

## 🌍 What Problem This Solves

Most security tooling is either:

* A paid, closed-source enterprise product
* A scattered pile of shell one-liners with no history or reporting
* Hard to audit, since you can't read the whole tool in one sitting

👉 **Suspicious Executable Detector** solves this by shipping as **one readable Python file** — CLI and web app together,
no hidden network calls, no telemetry, and a `selftest` command that proves every claim above
against a temporary database before you ever point it at your own machine.

## 💡 Core Concept

Instead of scattered, one-shot scripts:

💥 **Suspicious Executable Detector** uses a scan → store → score → report model

* Every scan is saved to SQLite, so you can compare runs over time
* Every finding carries evidence, not just a verdict
* Every chart is rendered server-side as SVG — nothing fetched from a CDN, nothing executed in
  the browser beyond the page itself

## 📊 Real Data, Hand-Rendered Visuals

This is **not** an animated mockup — it is a working tool that reads real data from this host or
the file/input you give it, and renders it with:

* 🎯 Server-side SVG charts (no JS charting library, no CDN)
* 📈 Scan-to-scan history and trend views
* 🔎 Filterable findings/results tables
* 🧭 A 404 handler and empty-state pages instead of blank crashes
* 💻 A CLI that mirrors everything the web app can do

## 🔥 Key Features (SEO Optimized)

* An executable whose filename claims to be a document (`invoice.pdf` that is really an ELF)
* A binary named after a system tool sitting outside a system directory
* Bidirectional text control characters in a filename
* Strings for deleting shadow copies or disabling recovery

## 🧩 What It Covers

* Attention gauge, coverage (including directories it could not read), and the files worth reading first — each with full indicator detail and a "mark as reviewed" button
* Every file examined, highest score first, with expandable indicators; filter by format, minimum score, free text
* Indicators grouped by type across all files — the fastest way to see "12 files tripped this, and here is when it is normal"
* Severity pie, files by format, most common indicators, an entropy-against-score scatter, files by directory, score distribution
* Every scan, review decision and export

## 🖥️ CLI

```
python3 suspicious_executable_detector.py <command> [options]

scan        triage one or more paths     --path P...  --quick  --all-files  --no-recurse
                                         --max-files N  --min-score N  --show N
inspect     one file in full detail      PATH  --quick
show [ID]   summary of one scan          --limit N  --min-score N
files       files from a scan            --scan ID  --format F  --search S
                                         --min-score N  --reviewed  --limit N
indicators  indicators grouped by type   --scan ID  --severity S
approve     record a file as reviewed    --file PATH | --sha256 HASH  --label L
revoke      remove a hash from the list  HASH
baseline    list reviewed files          --limit N
scans       list previous scans          --limit N
explain     what this is and its limits
serve       web app                      --host  --port  --debug
export      write a report               --format html|json|csv  --out F
logs        local event log              --level L  --limit N
purge       delete stored scans          --keep N | --all [--baseline]
selftest    verify every component (fixtures, temporary database)
version     versions, dependencies, disclaimer
```

## 🛠️ Tech Stack

* 🐍 Python 3.12+ (standard library only for the core logic)
* 🌶️ Flask — web app (optional; the CLI works without it)
* 🗄️ SQLite — scan history and findings storage
* 🖼️ Hand-generated SVG — charts, no external JS/CSS dependency


## 🎨 Design Philosophy

* 🌑 Read-only by default — nothing is changed on the host or target
* 🧠 Evidence-first — every finding shows *why*, not just *what*
* 📊 Data clarity over clutter
* ⚡ One file, fully auditable
* 🎯 Analyst-focused UX, both in the terminal and the browser

## 📈 SEO Keywords

Suspicious Executable Detector · Digital Forensics Tool · Cybersecurity CLI Utility · DFIR Dashboard · Security Audit Tool
· Network Forensics · Host Security Scanner · Python Security Tool · Offline Security Analysis ·
Open Source Security Utility

## ❓ Frequently Asked Questions (AEO)

**What does Suspicious Executable Detector do?**
Suspicious Executable Detector is a read-only Python CLI and web app that static triage of executables on one host. Parses ELF, PE and Mach-O headers, measures entropy, extracts strings and checks filesystem context, then orders what it found by how much it deserves a human's attention. Single Python file, a CLI and a 5-page web app, SQLite storage, SVG analytics, and a reviewed-file baseline.

**Does Suspicious Executable Detector send any data over the network or to third parties?**
No. Suspicious Executable Detector performs local analysis only. There is no telemetry, no external API calls beyond
what its own documented function explicitly requires (if any), and no data leaves the host
unless you export a report yourself.

**Does Suspicious Executable Detector modify my system?**
No. It is read-only. It inspects and reports; it does not change configuration, files, or
running services.

**Is Suspicious Executable Detector a replacement for professional security software?**
No. It is a heuristic, educational and portfolio-grade tool. See the disclaimer below.

**What do I need to run Suspicious Executable Detector?**
Python 3.12 or newer. Flask is required only if you want the web app; the CLI works without it.
Run `python3 suspicious_executable_detector.py selftest` first to verify your environment.

## ⚠️ Professional Disclaimer

🚨 **IMPORTANT — READ BEFORE RUNNING**

* ❌ This is **not** certified security software and carries **no warranty of any kind**.
* ❌ It does **not** replace a professional penetration test, a licensed forensic examiner, or
  commercial EDR/SIEM tooling.
* ❌ Findings are **heuristics, not proof**. A clean result does not mean a system is secure, and
  a flagged result does not mean it is compromised — verify everything manually.
* ✅ **Authorised use only.** Only run this against hosts, networks, files or accounts you own or
  have explicit written permission to test. Unauthorized scanning of systems you do not own or
  control may be illegal in your jurisdiction.
* ✅ **Read-only, offline by design.** No telemetry, no third-party services, no hidden network
  calls beyond what the tool's own documented purpose requires.
* ✅ The author accepts **no liability** for any loss, damage, misuse, or legal consequence
  arising from the use, misuse, or misinterpretation of this tool or its output.
* ✅ Reports produced by this tool can contain sensitive information (accounts, ports,
  configuration, personal data). Handle and share exported reports carefully.

This project is provided **"as is"**, for learning, portfolio demonstration, and authorised
security work only.

## 🚀 About Me

Hi, I'm **Karanam Shrivasta**, a Cyber Security enthusiast focused on:

* Digital Forensics
* Ethical Hacking
* Network Security
* AI in Cybersecurity

💥 Building real-world, working security tools — not mockups.

[GitHub](https://github.com/mrshrivasta) · [LinkedIn](https://www.linkedin.com/in/karanam-shrivasta/)
