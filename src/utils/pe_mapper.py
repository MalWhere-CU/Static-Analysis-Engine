"""PE file structure mapper.

Maps byte offsets to PE structures: sections, imports, strings, and metadata.
Used by the XAI pipeline to give semantic meaning to attribution regions.
"""

import os
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import pefile


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float
    characteristics: int


@dataclass
class ImportEntry:
    dll: str
    function: str
    offset: int  # file offset where the import entry resides


@dataclass
class StringEntry:
    value: str
    offset: int
    encoding: str  # 'ascii' or 'unicode'


@dataclass
class OffsetMapping:
    """Result of mapping a byte range to PE semantics."""
    start_offset: int
    end_offset: int
    section: Optional[str]
    section_info: Optional[Dict]
    strings: List[Dict]
    imports: List[Dict]
    raw_bytes_hex: str  # first 64 bytes as hex


class PEMapper:
    """Maps byte offsets to PE structures for a given PE file."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._pe = None
        self._sections: List[PESection] = []
        self._imports: List[ImportEntry] = []
        self._strings: List[StringEntry] = []
        self._file_bytes: bytes = b""

        self._load()

    def _load(self):
        """Parse PE file and extract structures."""
        with open(self.file_path, 'rb') as f:
            self._file_bytes = f.read()

        try:
            self._pe = pefile.PE(data=self._file_bytes)
        except pefile.PEFormatError:
            # Not a valid PE — still allow string/byte extraction
            self._pe = None

        if self._pe:
            self._parse_sections()
            self._parse_imports()

        self._extract_strings()

    def _parse_sections(self):
        """Extract section information."""
        if not self._pe:
            return
        for section in self._pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            self._sections.append(PESection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_offset=section.PointerToRawData,
                raw_size=section.SizeOfRawData,
                entropy=section.get_entropy(),
                characteristics=section.Characteristics,
            ))

    def _parse_imports(self):
        """Extract import table entries with their file offsets."""
        if not self._pe:
            return
        if not hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace') if entry.dll else "unknown"
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='replace') if imp.name else f"ord_{imp.ordinal}"
                # imp.struct_table gives file offset of the thunk
                offset = imp.struct_table.get_file_offset() if imp.struct_table else 0
                self._imports.append(ImportEntry(
                    dll=dll_name,
                    function=func_name,
                    offset=offset,
                ))

    def _extract_strings(self, min_length: int = 4):
        """Extract ASCII and Unicode strings with their file offsets."""
        # ASCII strings
        ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
        for match in ascii_pattern.finditer(self._file_bytes):
            self._strings.append(StringEntry(
                value=match.group().decode('ascii', errors='replace'),
                offset=match.start(),
                encoding='ascii',
            ))

        # Unicode (UTF-16LE) strings
        unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length)
        for match in unicode_pattern.finditer(self._file_bytes):
            try:
                decoded = match.group().decode('utf-16-le', errors='replace')
                self._strings.append(StringEntry(
                    value=decoded,
                    offset=match.start(),
                    encoding='unicode',
                ))
            except (UnicodeDecodeError, ValueError):
                pass

    def get_section_at_offset(self, offset: int) -> Optional[PESection]:
        """Return the PE section containing the given file offset."""
        for section in self._sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section
        # Check headers region
        if self._pe and offset < (self._pe.OPTIONAL_HEADER.SizeOfHeaders if self._pe.OPTIONAL_HEADER else 0):
            return PESection(
                name="PE_HEADERS",
                virtual_address=0,
                virtual_size=0,
                raw_offset=0,
                raw_size=self._pe.OPTIONAL_HEADER.SizeOfHeaders,
                entropy=0.0,
                characteristics=0,
            )
        # Check if offset is in overlay (data appended after all sections)
        if self._pe and self._sections:
            last_section = max(self._sections, key=lambda s: s.raw_offset + s.raw_size)
            overlay_start = last_section.raw_offset + last_section.raw_size
            if offset >= overlay_start:
                return PESection(
                    name="OVERLAY",
                    virtual_address=0,
                    virtual_size=0,
                    raw_offset=overlay_start,
                    raw_size=len(self._file_bytes) - overlay_start,
                    entropy=0.0,
                    characteristics=0,
                )
        # Check inter-section gaps (padding between sections)
        if self._pe and self._sections:
            header_end = self._pe.OPTIONAL_HEADER.SizeOfHeaders if self._pe.OPTIONAL_HEADER else 0
            if offset >= header_end:
                return PESection(
                    name="SECTION_GAP",
                    virtual_address=0,
                    virtual_size=0,
                    raw_offset=offset,
                    raw_size=0,
                    entropy=0.0,
                    characteristics=0,
                )
        return None

    def get_strings_in_range(self, start: int, end: int) -> List[StringEntry]:
        """Return all strings overlapping with the given byte range."""
        results = []
        for s in self._strings:
            s_end = s.offset + len(s.value) * (2 if s.encoding == 'unicode' else 1)
            # Check overlap
            if s.offset < end and s_end > start:
                results.append(s)
        return results

    def get_imports_in_range(self, start: int, end: int) -> List[ImportEntry]:
        """Return all imports whose thunk falls in the given range."""
        return [imp for imp in self._imports if start <= imp.offset < end]

    def map_offset_range(self, start: int, end: int) -> Dict:
        """
        Map a byte range to PE semantics.

        Returns dict with section, strings, imports, and raw hex for the range.
        """
        section = self.get_section_at_offset(start)
        strings = self.get_strings_in_range(start, end)
        imports = self.get_imports_in_range(start, end)

        # Get raw bytes (limit to 64 bytes for display)
        raw = self._file_bytes[start:min(end, start + 64)]
        raw_hex = raw.hex()

        return {
            "start_offset": start,
            "end_offset": end,
            "section": {
                "name": section.name,
                "raw_offset": section.raw_offset,
                "raw_size": section.raw_size,
                "entropy": round(section.entropy, 4),
            } if section else None,
            "strings": [
                {"value": s.value[:200], "offset": s.offset, "encoding": s.encoding}
                for s in strings[:20]  # limit output
            ],
            "imports": [
                {"dll": imp.dll, "function": imp.function, "offset": imp.offset}
                for imp in imports
            ],
            "raw_hex": raw_hex,
        }

    def get_all_imports(self) -> List[Dict]:
        """Return all parsed imports."""
        return [
            {"dll": imp.dll, "function": imp.function, "offset": imp.offset}
            for imp in self._imports
        ]

    def get_all_sections(self) -> List[Dict]:
        """Return all parsed sections."""
        return [
            {
                "name": s.name,
                "raw_offset": s.raw_offset,
                "raw_size": s.raw_size,
                "virtual_address": s.virtual_address,
                "virtual_size": s.virtual_size,
                "entropy": round(s.entropy, 4),
            }
            for s in self._sections
        ]

    def get_full_summary(self) -> Dict:
        """Return a summary of the PE file."""
        summary = {
            "file": self.file_path,
            "file_size": len(self._file_bytes),
            "is_pe": self._pe is not None,
            "sections": self.get_all_sections(),
            "num_imports": len(self._imports),
            "num_strings": len(self._strings),
        }
        if self._pe:
            summary["entry_point"] = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint
            summary["image_base"] = self._pe.OPTIONAL_HEADER.ImageBase
        return summary
