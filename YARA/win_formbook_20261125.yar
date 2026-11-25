rule win_formbook_20261125
{
    meta:
        description = "Auto-generated stub for win.formbook based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6a8f9e5911e3e527089de2e8a63a57d3fc68fd458fd6e303875d4b7bbe8cbf76
        // b787f6560a6bc7370f63376923e9d8433076655701edb331b95a6e0d35a680c6
        // 11b3f76d94cf66e4c02aa96bcbec88044d55c506ffe0c5bdc39b3fc3b2f185cf

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
