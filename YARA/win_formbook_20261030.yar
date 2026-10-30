rule win_formbook_20261030
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-30"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0fdd8680eee1762610d47515ace7b74b3ee715e93e5d1fbaecfa5b248fd1e187
        // f51df4b117f65f70272204d7eb4f7b15caa495fd777ba7701884ad35ec2f07b3

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
