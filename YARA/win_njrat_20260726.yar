rule win_njrat_20260726
{
    meta:
        description = "Auto-generated stub for win.njrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.njrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0268fde13e99c555ed4a4c6ef193b9ea
        // 155d1dce8e17b107b531b80b648f1a3fcbcbed764d76a39b0b3972d9424dd2f7

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
