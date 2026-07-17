rule win_salatstealer_20260717
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-17"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9a0cea11f75f63bbff8d0cea420787da972e78d8eb3baa14cd575f55bde369d8
        // 23285f10bb9b3002a24d3dbf865f07e1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
