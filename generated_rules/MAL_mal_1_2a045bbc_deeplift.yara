rule MAL_mal_1_2a045bbc_deeplift {
    meta:
        description = "Auto-generated rule from MalConv2 XAI attribution (deeplift)"
        author = "MalWhere Static Analysis Engine"
        date = "2026-06-13"
        confidence = "0.9991"
        hash1 = "2a045bbc471a99cecdc8ab5d7a7697455bc722a13b9cc3526c723744dd510811"
        source_file = "mal_1.exe"

    strings:
        $s1 = "708a2c19247e0449580d8ec4c9c0b64ab97b44bac5b307ce232cacfccd501a4f12a9097d4f6a6f33bb1dfd7c7bc1512227ac"  // score=1.0000
        $h1 = { 36 64 37 37 63 36 65 37 65 39 32 38 33 32 63 32 35 30 34 33 32 62 63 64 39 33 39 66 32 37 66 32 37 30 34 37 30 39 61 31 65 64 37 66 37 32 38 34 66 31 38 62 64 32 32 36 35 65 35 32 31 65 63 35 }  // .reloc, score=1.0000
        $h2 = { 00 01 02 03 04 05 08 09 08 09 0A 0B 0C 0D 0E 0F 02 03 04 05 08 09 06 07 08 09 0A 0B 0C 0D 0E 0F 00 01 04 05 08 09 06 07 08 09 0A 0B 0C 0D 0E 0F 04 05 08 09 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }  // .rdata, score=0.3069
        $h3 = { A6 01 00 45 33 C0 48 8D 0C 9B 48 8D 0C CA BA A0 0F 00 00 E8 28 FC FF FF 85 C0 74 11 FF 05 86 A8 01 00 FF C3 83 FB 0F 72 D3 B0 01 EB 09 33 C9 E8 08 00 00 00 32 C0 48 83 C4 20 5B C3 40 53 48 83 }  // .text, score=0.2538

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        3 of them
}
