rule win_formbook_20261023
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43
        // b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
