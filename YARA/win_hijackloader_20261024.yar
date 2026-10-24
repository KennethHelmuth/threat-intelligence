rule win_hijackloader_20261024
{
    meta:
        description = "Auto-generated stub for win.hijackloader based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.hijackloader"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d9f556865406a4671d53df11689b1f64
        // 0bc40efcb7690a9621778d2829c191e481b40efa70532e70c8dd6ab686a00f0e
        // 562d8f8381ad20a7140a5b7a060ff4ee60484eb815bf442f7071e293678ca95d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
