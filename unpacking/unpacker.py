"""
=============================================================================
  Executable Packing Methods & Unpacking Strategies for Malware Analysis
=============================================================================

OVERVIEW
--------
Packers fall into three broad families, each with increasing difficulty:

  1. COMPRESSORS   — only compress; no anti-analysis (UPX, ASPack, MPRESS, FSG, …)
  2. CRYPTERS      — encrypt + obfuscate; static analysis extremely hard (Yoda's, PolyCrypt, …)
  3. PROTECTORS    — compressors + crypters + anti-debug/VM/dump (Themida, VMProtect, Armadillo, …)

This file covers detection *and* automated unpacking for each category.

RESOURCES
---------
  - ACM Survey on packed PE files:  https://dl.acm.org/doi/10.1145/3530810
  - Unipacker (emulation-based):    https://github.com/unipacker/unipacker
  - PyPackerDetect (Cylance):       https://github.com/cylance/PyPackerDetect
  - Pypackerdetect (packing-box):   https://github.com/packing-box/pypackerdetect
  - ANY.RUN packer/crypter guide:   https://any.run/cybersecurity-blog/packers-and-crypters-in-malware/
  - Themida/VMProtect analysis:     https://any.run/cybersecurity-blog/vmprotect-themida-malware-analysis/
  - Huntress packer explainer:      https://www.huntress.com/cybersecurity-101/topic/malware-packer
  - x64Unpack paper (VMProtect):    https://repository.hanyang.ac.kr/handle/20.500.11754/168823

DEPENDENCIES
------------
  pip install pefile unipacker yara-python python-dotenv
  # For VMProtect/64-bit samples: pip install qiling
"""

import os
import math
import shutil
import struct
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# ── tool paths from .env ──────────────────────────────────────────────────────
UPX_PATH      = os.getenv("UPX_PATH", "upx")
UNIPACKER_PATH = os.getenv("UNIPACKER_PATH", "unipacker")


# =============================================================================
# 1.  PACKER DETECTION
# =============================================================================

# ── 1a. Section-name signatures ──────────────────────────────────────────────
# Source: github.com/cylance/PyPackerDetect / ANY.RUN blog
SECTION_SIGNATURES: dict[str, str] = {
    # UPX
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    # MPRESS
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    # ASPack
    ".aspack": "ASPack", ".adata": "ASPack", "ASPack": "ASPack", ".ASPack": "ASPack",
    # VMProtect
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    # Themida / WinLicense
    ".themida": "Themida", ".taggant": "Themida",
    # FSG
    "FSG!": "FSG",
    # NsPack
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    "nsp0": "NsPack",  "nsp1": "NsPack",  "nsp2": "NsPack",
    # PECompact
    ".pec1": "PECompact", ".pec2": "PECompact",
    # PEtite
    ".petite": "PEtite",
    # MEW
    "MEW": "MEW",
    # Armadillo
    ".armadillo": "Armadillo",
    # PELock
    ".pelock": "PELock",
    # RLPack
    ".packed": "RLPack",
    # Enigma
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    # Obsidium
    ".obsidium": "Obsidium",
    # kkrunchy
    "kkrunchy": "kkrunchy",
}

# ── 1b. Entry-point byte signatures (PEiD-style) ─────────────────────────────
# Each entry: (hex_pattern_with_wildcards, packer_name)
# '??' = any byte wildcard
EP_SIGNATURES: list[tuple[list, str]] = [
    ([0x60, 0xBE, None, None, None, 0x00, 0x8D, 0xBE],  "UPX"),
    ([0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83],  "UPX 0.50-0.70"),
    ([0x60, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00],         "UPX modified"),
    ([0x75, 0x00, 0xE9],                                  "ASPack 1.05b"),
    ([0x90, 0x90, 0x75, 0x00, 0xE9],                      "ASPack 1.061b"),
    ([0x90, 0x90, 0x90, 0x75, 0x01, 0x90, 0xE9],          "ASPack 1.08"),
    ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00],   "MPRESS"),
    ([0x68, None, None, None, 0x00, 0xE8, 0x00, 0x00],   "FSG 1.33"),
    ([0xBE, None, None, None, 0x00, 0xAD, 0x50, 0x52],   "PEtite"),
]


def _match_ep_sig(data: bytes, sig: list) -> bool:
    if len(data) < len(sig):
        return False
    return all(s is None or data[i] == s for i, s in enumerate(sig))


@dataclass
class PackerDetectionResult:
    is_packed: bool = False
    packer_name: str = "Unknown"
    confidence: str = "None"          # "High" | "Medium" | "Low"
    method: str = ""                  # how it was detected
    overall_entropy: float = 0.0
    section_entropies: dict = field(default_factory=dict)


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string.  Values > 7.0 strongly suggest
    compression or encryption.
    Reference: https://github.com/mandiant/capa/issues/1401
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def detect_packer(file_path: str) -> PackerDetectionResult:
    """
    Multi-method packer detector using:
      (1) PE section names
      (2) Entry-point byte signatures
      (3) Shannon entropy

    Returns a PackerDetectionResult with the most likely packer and confidence.
    """
    result = PackerDetectionResult()

    try:
        import pefile
        pe = pefile.PE(file_path)
    except Exception as e:
        result.method = f"pefile parse error: {e}"
        return result

    # ── Method 1: section names ───────────────────────────────────────────────
    for section in pe.sections:
        name = section.Name.decode(errors="replace").rstrip("\x00").strip()
        if name in SECTION_SIGNATURES:
            result.is_packed     = True
            result.packer_name   = SECTION_SIGNATURES[name]
            result.confidence    = "High"
            result.method        = f"section name '{name}'"

    # ── Method 2: entry-point signatures ─────────────────────────────────────
    if not result.is_packed:
        try:
            ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            with open(file_path, "rb") as f:
                f.seek(ep_offset)
                ep_bytes = f.read(32)
            for sig, name in EP_SIGNATURES:
                if _match_ep_sig(ep_bytes, sig):
                    result.is_packed   = True
                    result.packer_name = name
                    result.confidence  = "High"
                    result.method      = "entry-point byte signature"
                    break
        except Exception:
            pass

    # ── Method 3: entropy ─────────────────────────────────────────────────────
    with open(file_path, "rb") as f:
        raw = f.read()
    result.overall_entropy = calculate_entropy(raw)

    high_entropy_sections = []
    for section in pe.sections:
        sec_data    = section.get_data()
        sec_entropy = calculate_entropy(sec_data)
        sec_name    = section.Name.decode(errors="replace").rstrip("\x00").strip()
        result.section_entropies[sec_name] = round(sec_entropy, 3)
        if sec_entropy > 6.8:
            high_entropy_sections.append(sec_name)

    if not result.is_packed and (result.overall_entropy > 6.8 or high_entropy_sections):
        result.is_packed   = True
        result.packer_name = "Unknown (high entropy)"
        result.confidence  = "Medium"
        result.method      = (f"entropy={result.overall_entropy:.2f}; "
                               f"high-entropy sections={high_entropy_sections}")

    # ── Method 4: low import count heuristic ─────────────────────────────────
    if not result.is_packed:
        try:
            import_count = sum(
                len(entry.imports)
                for entry in pe.DIRECTORY_ENTRY_IMPORT
            ) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0
            if import_count < 5:
                result.is_packed   = True
                result.packer_name = "Unknown (few imports)"
                result.confidence  = "Low"
                result.method      = f"only {import_count} imports"
        except Exception:
            pass

    pe.close()
    return result


# =============================================================================
# 2.  PACKER-SPECIFIC UNPACKERS
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# PACKER 1: UPX  (already in your codebase — shown here for completeness)
# ─────────────────────────────────────────────────────────────────────────────
# What it is: The most common free compressor. Uses NRV/LZMA compression and
#             leaves a small decompression stub.
# Detection:  Section names UPX0/UPX1; entry-point signature 60 BE ??;
#             `-d` flag in UPX itself.
# Unpacking:  UPX natively supports unpacking with `upx -d`.
# Reference:  https://upx.github.io/
# ─────────────────────────────────────────────────────────────────────────────

class UPXUnpacker:
    """Unpack a UPX-packed PE using the UPX binary (native support)."""

    @staticmethod
    def unpack(file_path: str, upx_path: str = UPX_PATH) -> Optional[str]:
        tmp        = tempfile.mkdtemp()
        input_copy = os.path.join(tmp, "input.exe")
        output     = os.path.join(tmp, "unpacked.exe")

        shutil.copy2(file_path, input_copy)
        try:
            r = subprocess.run(
                [upx_path, "-d", "-o", output, input_copy],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if r.returncode == 0 and os.path.exists(output):
                print("[UPX] Unpacked successfully.")
                return output
            print(f"[UPX] Failed: {r.stderr.strip()}")
        except FileNotFoundError:
            print(f"[UPX] upx binary not found at '{upx_path}'.")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 2: ASPack
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Commercial Win32 compressor with a high compression ratio.
#             Widely used in legitimate software and by malware authors.
# Detection:  Section names .aspack/.adata; entry-point sig 75 00 E9.
# Unpacking:  Unipacker handles ASPack natively via emulation.
# Reference:  http://www.aspack.com/
#             https://github.com/unipacker/unipacker
# ─────────────────────────────────────────────────────────────────────────────

class ASPackUnpacker:
    """Unpack ASPack-packed PE using Unipacker (emulation-based)."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="ASPack")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 3: MPRESS
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Free packer that supports x86, x64, and CLI executables.
#             Creates distinctive .MPRESS1 / .MPRESS2 sections.
# Detection:  Section names .MPRESS1/.MPRESS2.
# Unpacking:  Unipacker (MPRESSUnpacker built in).
# Reference:  https://www.matcode.com/mpress.htm
#             Section names: github.com/cylance/PyPackerDetect
# ─────────────────────────────────────────────────────────────────────────────

class MPRESSUnpacker:
    """Unpack MPRESS-packed PE using Unipacker."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="MPRESS")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 4: FSG (Fast Small Good)
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Freeware packer optimised for very small output size.
#             Minimal stub, common in older malware families.
# Detection:  Section name FSG!; entry-point sig 68 ?? ?? ?? 00 E8 00 00.
# Unpacking:  Unipacker (FSGUnpacker built in).
# Reference:  https://github.com/unipacker/unipacker
# ─────────────────────────────────────────────────────────────────────────────

class FSGUnpacker:
    """Unpack FSG-packed PE using Unipacker."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="FSG")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 5: PEtite
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Freeware packer similar to ASPack. Creates .petite section.
# Detection:  Section name .petite; entry-point sig BE ?? ?? ?? 00 AD 50 52.
# Unpacking:  Unipacker (PEtiteUnpacker built in).
# Reference:  https://www.un4seen.com/petite/
# ─────────────────────────────────────────────────────────────────────────────

class PEtiteUnpacker:
    """Unpack PEtite-packed PE using Unipacker."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="PEtite")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 6: MEW (MEW 11 SE)
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Freeware packer designed for small 32-bit executables.
# Detection:  Section name "MEW"; very low import count.
# Unpacking:  Unipacker (MEWUnpacker built in).
# ─────────────────────────────────────────────────────────────────────────────

class MEWUnpacker:
    """Unpack MEW-packed PE using Unipacker."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="MEW")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 7: PECompact
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Commercial compressor with optional encryption plugins.
#             Creates .pec1/.pec2 sections.
# Detection:  Section names .pec1/.pec2.
# Unpacking:  Unipacker (PECompactUnpacker built in).
# Reference:  http://www.bitsum.com/pecompact.asp
# ─────────────────────────────────────────────────────────────────────────────

class PECompactUnpacker:
    """Unpack PECompact-packed PE using Unipacker."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="PECompact")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 8: NsPack
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Chinese compressor. Creates .nsp0/.nsp1/.nsp2 sections.
# Detection:  Section names nsp0/nsp1/nsp2.
# Unpacking:  Unipacker generic fallback (emulate until OEP, then dump).
# ─────────────────────────────────────────────────────────────────────────────

class NsPackUnpacker:
    """Unpack NsPack via Unipacker generic mode."""

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        return _unipacker_unpack(file_path, label="NsPack")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 9: Themida / WinLicense  (PROTECTOR — hardest tier)
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Commercial protector combining compression + encryption +
#             code virtualisation + anti-debug + anti-VM.
#             Most prevalent protector in the wild (>50 % of protected samples).
#             Creates .themida or random-name sections.
# Detection:  Section names .themida/.taggant; or blank/random section names.
# Unpacking:  Best-effort via Unipacker generic strategy (emulate → dump).
#             For virtualized code blocks, only partial unpacking is achievable
#             without manual reverse-engineering.
# Reference:  https://any.run/cybersecurity-blog/vmprotect-themida-malware-analysis/
#             https://arxiv.org/pdf/2112.11289  (prevalence study)
# ─────────────────────────────────────────────────────────────────────────────

class ThemidaUnpacker:
    """
    Best-effort Themida/WinLicense unpacking via Unipacker.

    NOTE: Themida uses code virtualisation. This will recover the unpacked
    PE body but virtualised code blocks remain as pseudo-bytecode.
    For deeper analysis use x64dbg + ScyllaHide manually.
    """

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        print("[Themida] Attempting generic emulation-based unpack (partial).")
        return _unipacker_unpack(file_path, label="Themida")


# ─────────────────────────────────────────────────────────────────────────────
# PACKER 10: VMProtect  (PROTECTOR — hardest tier)
# ─────────────────────────────────────────────────────────────────────────────
# What it is: Commercial protector that converts assembly into custom VM
#             bytecode interpreted at runtime. Sections named .vmp0/.vmp1.
#             Resists professional RE attempts.
# Detection:  Section names .vmp0/.vmp1/.vmp2.
# Unpacking:  For 32-bit → Unipacker generic.
#             For 64-bit → Qiling-based emulation (see below).
# Reference:  https://vmpsoft.com/
#             https://any.run/cybersecurity-blog/vmprotect-themida-malware-analysis/
#             x64Unpack paper: https://repository.hanyang.ac.kr/handle/20.500.11754/168823
# ─────────────────────────────────────────────────────────────────────────────

class VMProtectUnpacker:
    """
    VMProtect unpacking:
      - 32-bit samples → Unipacker generic emulation
      - 64-bit samples → Qiling framework emulation + memory dump
    """

    @staticmethod
    def _is_64bit(file_path: str) -> bool:
        try:
            import pefile
            pe = pefile.PE(file_path, fast_load=True)
            result = pe.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64
            pe.close()
            return result
        except Exception:
            return False

    @staticmethod
    def unpack(file_path: str) -> Optional[str]:
        if VMProtectUnpacker._is_64bit(file_path):
            return VMProtectUnpacker._unpack_64bit(file_path)
        return _unipacker_unpack(file_path, label="VMProtect-32")

    @staticmethod
    def _unpack_64bit(file_path: str) -> Optional[str]:
        """
        64-bit VMProtect via Qiling emulation.
        Requires:  pip install qiling
                   Windows rootfs for Qiling (see https://github.com/qilingframework/qiling)

        WINDOWS_ROOTFS env var must point to a valid Qiling Windows rootfs directory.
        """
        rootfs = os.getenv("WINDOWS_ROOTFS")
        if not rootfs:
            print("[VMProtect-64] WINDOWS_ROOTFS not set. Skipping Qiling unpack.")
            return None
        try:
            from qiling import Qiling
            from qiling.const import QL_VERBOSE

            tmp        = tempfile.mkdtemp()
            output     = os.path.join(tmp, "vmp_unpacked.exe")

            ql = Qiling([file_path], rootfs, verbose=QL_VERBOSE.OFF)

            TIMEOUT = 30  # seconds of emulation before we dump

            def timeout_hook(ql):
                ql.emu_stop()

            ql.add_fs_mapper(r"C:\\", rootfs)
            ql.run(timeout=TIMEOUT * (10 ** 6))   # timeout in microseconds

            # Read the unpacked image from emulated memory
            import pefile
            pe     = pefile.PE(file_path, fast_load=True)
            base   = ql.mem.read(pe.OPTIONAL_HEADER.ImageBase,
                                  pe.OPTIONAL_HEADER.SizeOfImage)
            with open(output, "wb") as f:
                f.write(base)

            print(f"[VMProtect-64] Dumped {len(base)} bytes via Qiling.")
            return output

        except ImportError:
            print("[VMProtect-64] Qiling not installed.  pip install qiling")
        except Exception as e:
            print(f"[VMProtect-64] Qiling error: {e}")
        return None


# =============================================================================
# 3.  SHARED HELPER: Unipacker subprocess wrapper
# =============================================================================
# Unipacker is emulation-based and platform-independent.
# It natively supports: UPX, ASPack, PEtite, FSG, MEW, MPRESS, PECompact.
# For unknown packers it falls back to a generic "emulate until OEP" strategy.
# Reference: https://github.com/unipacker/unipacker

def _unipacker_unpack(file_path: str, label: str = "Unknown") -> Optional[str]:
    """
    Run Unipacker on *file_path* and return the path of the dumped PE,
    or None on failure.

    Unipacker is invoked as a subprocess so it works regardless of Python
    version constraints (it requires Python 3.6+).
    """
    tmp    = tempfile.mkdtemp()
    output = os.path.join(tmp, "unpacked.exe")

    try:
        r = subprocess.run(
            [UNIPACKER_PATH, "--output", output, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        if os.path.exists(output) and os.path.getsize(output) > 0:
            print(f"[{label}] Unipacker succeeded → {output}")
            return output
        print(f"[{label}] Unipacker did not produce output.\n"
              f"  stdout: {r.stdout[:300]}\n"
              f"  stderr: {r.stderr[:300]}")
    except FileNotFoundError:
        print(f"[{label}] Unipacker binary not found at '{UNIPACKER_PATH}'.")
    except subprocess.TimeoutExpired:
        print(f"[{label}] Unipacker timed out after 120 s.")
    except Exception as e:
        print(f"[{label}] Unexpected error: {e}")
    return None


# =============================================================================
# 4.  DISPATCHER: PackerHandler
# =============================================================================

# Map detected packer name → unpacker class
UNPACKER_MAP: dict[str, type] = {
    "UPX":          UPXUnpacker,
    "ASPack":       ASPackUnpacker,
    "MPRESS":       MPRESSUnpacker,
    "FSG":          FSGUnpacker,
    "PEtite":       PEtiteUnpacker,
    "MEW":          MEWUnpacker,
    "PECompact":    PECompactUnpacker,
    "NsPack":       NsPackUnpacker,
    "Themida":      ThemidaUnpacker,
    "VMProtect":    VMProtectUnpacker,
}

# Packers that also partially match sub-strings
UNPACKER_PARTIAL_MAP: list[tuple[str, type]] = [
    ("UPX",       UPXUnpacker),
    ("ASPack",    ASPackUnpacker),
    ("MPRESS",    MPRESSUnpacker),
    ("FSG",       FSGUnpacker),
    ("PEtite",    PEtiteUnpacker),
    ("MEW",       MEWUnpacker),
    ("PECompact", PECompactUnpacker),
    ("NsPack",    NsPackUnpacker),
    ("Themida",   ThemidaUnpacker),
    ("VMProtect", VMProtectUnpacker),
]


class PackerHandler:
    """
    Drop-in replacement and extension of the original UnpackFile class.

    Usage
    -----
    result   = PackerHandler.detect(file_path)
    unpacked = PackerHandler.unpack(file_path)   # detects + unpacks
    PackerHandler.cleanup(unpacked_path)
    """

    @staticmethod
    def detect(file_path: str) -> PackerDetectionResult:
        """Return packer detection results without unpacking."""
        res = detect_packer(file_path)
        print(f"[Detect] packed={res.is_packed}  packer={res.packer_name}  "
              f"confidence={res.confidence}  method={res.method}  "
              f"entropy={res.overall_entropy:.2f}")
        return res

    @staticmethod
    def unpack(file_path: str) -> str:
        """
        Detect the packer, run the appropriate unpacker, and return the path
        to the unpacked file.  Falls back to the original path if unpacking
        fails.
        """
        res = PackerHandler.detect(file_path)

        if not res.is_packed:
            print("[Unpack] File appears unpacked — skipping.")
            return file_path

        # exact match first
        unpacker_cls = UNPACKER_MAP.get(res.packer_name)

        # partial / substring match
        if unpacker_cls is None:
            for key, cls in UNPACKER_PARTIAL_MAP:
                if key.lower() in res.packer_name.lower():
                    unpacker_cls = cls
                    break

        if unpacker_cls is None:
            print(f"[Unpack] No specific unpacker for '{res.packer_name}'. "
                  "Trying Unipacker generic fallback.")
            result = _unipacker_unpack(file_path, label="Generic")
            return result if result else file_path

        result = unpacker_cls.unpack(file_path)
        return result if result else file_path

    @staticmethod
    def cleanup(unpacked_path: str) -> None:
        """Remove the temporary directory created during unpacking."""
        try:
            folder = os.path.dirname(unpacked_path)
            if folder and os.path.isdir(folder):
                shutil.rmtree(folder)
                print("[Cleanup] Temporary directory removed.")
        except Exception as e:
            print(f"[Cleanup] Error: {e}")


# =============================================================================
# 5.  VALIDATION HELPER
# =============================================================================

def validate_unpack(original_path: str, unpacked_path: str) -> bool:
    """
    Simple post-unpack sanity check:
      - Unpacked file is larger (compression was reversed)
      - Unpacked entropy is lower (data is less random)
      - Unpacked file has more printable strings

    Returns True if the unpacked file looks plausibly better.
    """
    if not unpacked_path or not os.path.exists(unpacked_path):
        return False

    orig_size  = os.path.getsize(original_path)
    unp_size   = os.path.getsize(unpacked_path)

    with open(original_path, "rb") as f:
        orig_entropy = calculate_entropy(f.read())
    with open(unpacked_path, "rb") as f:
        unp_data    = f.read()
    unp_entropy = calculate_entropy(unp_data)

    # count printable ASCII strings of length >= 4
    def count_strings(data: bytes, min_len: int = 4) -> int:
        count = cur = 0
        for b in data:
            if 0x20 <= b < 0x7F:
                cur += 1
            else:
                if cur >= min_len:
                    count += 1
                cur = 0
        return count

    orig_strings = count_strings(bytes(open(original_path, "rb").read()))
    unp_strings  = count_strings(unp_data)

    print(f"[Validate] size  : {orig_size} → {unp_size} bytes")
    print(f"[Validate] entropy: {orig_entropy:.2f} → {unp_entropy:.2f}")
    print(f"[Validate] strings: {orig_strings} → {unp_strings}")

    return unp_size > orig_size or unp_entropy < orig_entropy - 0.5


# =============================================================================
# 6.  QUICK-REFERENCE TABLE (printed on import)
# =============================================================================

PACKER_REFERENCE = """
┌─────────────────┬────────────┬────────────────────────────────┬──────────────────────────────┐
│ Packer          │ Category   │ Detection Signal               │ Unpacking Approach           │
├─────────────────┼────────────┼────────────────────────────────┼──────────────────────────────┤
│ UPX             │ Compressor │ UPX0/UPX1 sections; EP sig     │ upx -d (native)              │
│ ASPack          │ Compressor │ .aspack section; EP sig        │ Unipacker (built-in support) │
│ MPRESS          │ Compressor │ .MPRESS1/.MPRESS2 sections     │ Unipacker (built-in support) │
│ FSG             │ Compressor │ FSG! section; EP sig           │ Unipacker (built-in support) │
│ PEtite          │ Compressor │ .petite section; EP sig        │ Unipacker (built-in support) │
│ MEW             │ Compressor │ MEW section; tiny imports      │ Unipacker (built-in support) │
│ PECompact       │ Compressor │ .pec1/.pec2 sections           │ Unipacker (built-in support) │
│ NsPack          │ Compressor │ .nsp0/.nsp1/.nsp2 sections     │ Unipacker generic fallback   │
│ Themida         │ Protector  │ .themida/.taggant or random    │ Unipacker generic (partial)  │
│ VMProtect       │ Protector  │ .vmp0/.vmp1/.vmp2 sections     │ Unipacker (32-bit)           │
│                 │            │                                │ Qiling emulation (64-bit)    │
│ Unknown/custom  │ Crypter    │ High entropy; few imports      │ Unipacker generic fallback   │
└─────────────────┴────────────┴────────────────────────────────┴──────────────────────────────┘

Difficulty tiers
  ● Easy      — UPX, FSG, MPRESS, MEW         → fully automated, seconds
  ● Medium    — ASPack, PEtite, PECompact      → automated via Unipacker
  ● Hard      — Themida, VMProtect, Armadillo  → partial; manual RE often required
  ● Very Hard — Custom crypters (Emotet, etc.) → manual dynamic analysis in x64dbg
"""

if __name__ == "__main__":
    print(PACKER_REFERENCE)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================
# from packing_unpacking_guide import PackerHandler, validate_unpack
#
# file = "sample.exe"
# unpacked = PackerHandler.unpack(file)
# if validate_unpack(file, unpacked):
#     print("Unpacking successful — proceeding to static analysis.")
# PackerHandler.cleanup(unpacked)