rule win_njrat_20261114
{
    meta:
        description = "Auto-generated stub for win.njrat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-14"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.njrat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // af1669913e244deebb9496a33264741b
        // 8afc276d54258cde26aa5259a4d51729
        // 25c1dca57b882d184f6a0c426ea06c62
        // 2057f65c6a9aee75b7c86ee73b61816a805a38581dfd18d229f6b5741fd9506b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
