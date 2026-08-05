rule win_formbook_20260805
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e0bf699a9016ef9a7740953c6ec4feb0
        // 438a199c60026b897fdda4da23d69e103cad34864a070d1b7659cf462628505f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
