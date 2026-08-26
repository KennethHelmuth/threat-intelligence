rule win_pure_rat_20260826
{
    meta:
        description = "Auto-generated stub for win.pure_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.pure_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 150cd29ec3f3156808da6121512c6bfc
        // 3b898adef43e54e9682f1358401ba2300ec3f39de75e2939d23e2bd60a725de6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
