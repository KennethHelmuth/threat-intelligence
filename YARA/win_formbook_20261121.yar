rule win_formbook_20261121
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-21"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 846f99ae97596408069270acd2bdff9d45a3c23d547040c65d23348da50b0f9c
        // e801820dc15bd2986ba90b05146915d3f79197c39d71c279c8f283a4f48f6ba9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
