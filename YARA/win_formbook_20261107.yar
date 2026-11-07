rule win_formbook_20261107
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-07"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6bfeb99e0aa982a6f6de1515e290e42e0a039decad9335859c85151265aff102
        // 4cde1a56605bb940e269953430cad45fc0e5046ca48f39a4f03029fb7c8c0f58

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
