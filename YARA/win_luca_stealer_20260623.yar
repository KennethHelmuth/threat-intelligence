rule win_luca_stealer_20260623
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0acfe0a8740e071874d3b0789ed5cd30
        // 817ac7a4ee5b546a812b129c9b9cfbb4581988bd95ac3e2a32a83b82f1bf430c
        // ba3281bb9c624619a22b1e506f23fe46
        // 060618b911a7022394c88e195aa477157d366363f76ed4b86f0cc3b635908cc3

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
