rule win_acr_stealer_20260705
{
    meta:
        description = "Auto-generated stub for win.acr_stealer based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.acr_stealer"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 4393ba303809c3ce1e5edcf4fa73d2f6
        // 8cd18949fe86667303cd19c683310d55
        // 8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f
        // 5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40
        // 3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72
        // a23a1b44ccc709bcbbc23ee3cd6fb342

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
