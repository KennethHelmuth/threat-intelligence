rule py_rn_stealer_20261013
{
    meta:
        description = "Auto-generated stub for py.rn_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.rn_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9d02e370b7c79d2472d96af30c38e4fca1181710f682ddbdd12059da645ac999
        // e96fd190a093e47ad5cbed527304ed06

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
