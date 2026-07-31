rule win_prb_backdoor
{
    meta:
        description = "Auto-generated stub for win.prb_backdoor based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-31"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.prb_backdoor"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 61858e50c96a6f37957e1d6e3249ddb49ebd5c592ddce8dacf039404897afe45
        // 2980c33b9f0de038fc408602fbf34187

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
