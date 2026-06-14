# 🛡️ Static Analysis Engine

An automated, containerized static preprocessing and signature analysis engine for advanced malware inspection. 

This repository leverages a multi-container pipeline that dynamically identifies file types, applies tailored static unpacking or extraction routines, and passes clean payloads downstream to a high-fidelity YARA scanning layer and LLM parsing module.

---

## 🛠️ System Architecture & Unpacking Pipeline


Previously, this tool only executed basic `UPX -d` decompression flags. It has been re-architected into a multi-tiered static preprocessing pipeline. 

Instead of routing binaries through slow, complex CPU emulators (which defeats the performance speed-run of static preprocessing), it relies on `die-python` (Detect It Easy) to dynamically flag structures and route them into safe, lightning-fast static extraction layers:

<h1>Design V1.0</h1>
<img src="design-v1.0.jpg" alt="design" width="800"/>


### Supported Extraction Capabilities
1. **Native PE Compression:** Unpacks binaries compressed with `UPX` cleanly.
2. **.NET Assemblies:** Automatically fixes obfuscated or packed metadata structures using `de4dot`.
3. **Python Script Bundlers:** Detects PyInstaller or py2exe stubs and extracts raw source data via `pyinstxtractor`.
4. **Installer Packages & SFX Drop-zones:** Extracts internal deployment structures via `7z` (NSIS, Inno Setup, Self-Extracting archives).
5. **Heavy Protectors Bypass:** Flags advanced virtualizers (`Themida`, `VMProtect`) safely as packed, but skips execution completely to avoid engine deadlocks—passing original layers cleanly down to the dedicated Dynamic VM analysis stage.

---

## 🚀 Getting Started (Docker Compose Environment)

The entire static analysis suite—including system assets, local database frameworks, and memory caching layers—is fully containerized. **Do not execute these scripts directly on your host operating system to prevent malware contamination.**

### 1. Setup Configuration
Clone the repository and instantiate your localized environment variables:
```bash
git clone [https://github.com/MalWhere-CU/Static-Analysis-Engine](https://github.com/MalWhere-CU/Static-Analysis-Engine)
cd Static-Analysis-Engine
```

Create a .env file inside the root directory:
```.env
OPENAI_API_KEY=your_openai_api_key_here
DB_PATH=rules.db
REDIS_HOST=redis
REDIS_PORT=6379
```


### 2. Launching the Whole Static Suite
To spin up the multi-container application layer (Python application worker nodes + isolated Redis caching database clusters):
```bash
docker compose up --build
```

### 3. Open an Interactive Terminal Inside Your Container
Run this command in your project root terminal to spin up your container and drop straight into its bash shell:
```bash
docker compose run --rm --entrypoint /bin/bash app
```

<hr>
<h2>YARA Rules</h2>
<p> Reference: <a href="https://github.com/Neo23x0/signature-base">Neo23x0/Signature_Based</a>
<br/> This repo is the most updated yara rules repo I found
<br/> It currently contains 737 Rules
</p>


<h2>Limitations & Future Work</h2>

<p>While this tool effectively handles common packers, advanced malware employs several techniques to thwart automated analysis. Future iterations of this module will aim to address the following challenges:</p>

<details open>
<summary><b>1. Custom Crypters (Signature Evasion)</b></summary>
<p>
    <b>The Challenge:</b> Many threat actors use "private" crypters that lack public signatures. In these cases, <code>die-python</code> will return no results, and generic unpacking stubs may fail.
    <br><br>
    <b>Future Work:</b> Implement <i>OEP (Original Entry Point)</i> detection logic. This involves identifying the "Tail Jump"—the final instruction in a packer stub that transitions execution to the real payload. We plan to integrate <b>Scylla</b>-based dumping to reconstruct the Import Address Table (IAT) once the OEP is reached.
</p>

</details>

<details>
<summary><b>2. Anti-Emulation & Code Virtualization</b></summary>
<p>
    <b>The Challenge:</b> High-end protectors like <b>Themida</b> and <b>VMProtect</b> detect the <i>Unicorn Engine</i> by identifying CPU timing discrepancies or unimplemented obscure instructions. Furthermore, they "virtualize" x86 code into a custom bytecode format.
    <br><br>
    <b>Future Work:</b> Integrate <b>ScyllaHide</b> hooks to mask the emulation environment and explore <b>VTIL (Virtual Tooling Intermediate Language)</b> for static devirtualization of protected code blocks.
</p>
</details>

<details>
<summary><b>3. Language-Specific Bundlers (Python/Go)</b></summary>
<p>
    <b>The Challenge:</b> Tools like <b>PyInstaller</b> don't pack code; they bundle a filesystem. Standard unpacking engines see these as valid, non-packed executables, yet the source remains hidden in <code>.pyc</code> bytecode.
    <br><br>
    <b>Future Work:</b> Add a detection layer for the <code>PYINST</code> signature. If detected, the module will automatically trigger <code>pyinstxtractor</code> and <code>pycdc</code> to recover the original <code>.py</code> source files.
</p>

</details>

<br>


<hr>