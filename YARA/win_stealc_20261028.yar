rule win_stealc_20261028
{
    meta:
        description = "Auto-generated stub for win.stealc based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // C8C98F125AD6593BE01F56A833384B03F0F514800026B2270A6604BC5E1997BE
        // 28F4630B283F8E821AC37CB3A3E6703C78DCC1DC95FBDE039E18971D032C29F3
        // 09183c07bf99667be170cd9759d7ea7fd14ac9b132336633e7ff51da02d28535
        // 20e2ce809ce5c3938ea58fe092d835b8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
