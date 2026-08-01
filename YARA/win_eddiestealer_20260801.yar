rule win_eddiestealer_20260801
{
    meta:
        description = "Auto-generated stub for win.eddiestealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-01"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.eddiestealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2cfaefe80e05fe0f093cf5c382d7c77f
        // ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
