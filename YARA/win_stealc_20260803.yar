rule win_stealc_20260803
{
    meta:
        description = "Auto-generated stub for win.stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-03"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 47854afb3cfeb64a85dda148e00e5ca83168f431a28e5c5fb28733e37f484b13
        // 4f8d31ea9c92ca7d2da3c6438f1c8ea1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
