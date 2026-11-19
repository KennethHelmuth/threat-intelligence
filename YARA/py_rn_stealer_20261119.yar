rule py_rn_stealer_20261119
{
    meta:
        description = "Auto-generated stub for py.rn_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-19"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.rn_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a
        // baf7e87ccbf9f1085805c96793f24e90

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
