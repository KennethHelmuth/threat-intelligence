rule win_arkei_stealer
{
    meta:
        description = "Auto-generated stub for win.arkei_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-08"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.arkei_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 17c783bb84f17edb43a538f0dfbeb1e9
        // 79a00dc593777f03f4de27e234f44908a91d600766f34b40f59aa2100000dd09

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
