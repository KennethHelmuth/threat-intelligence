rule cursor_ide
{
    meta:
        description = "Auto-generated stub for cursor_ide based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-03"
        version     = "1.0"
        source      = "OTX"
        family      = "cursor_ide"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f49bcd657ef1e626e85ce858958c1769
        // 3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081
        // 7d52fa561468f0c77bca112f8393399dec078d02
        // 6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731
        // 80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c
        // fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
