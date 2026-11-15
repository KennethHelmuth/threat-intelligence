rule win_salatstealer_20261115
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 43283be995f6c8e0fa1f839f45f3bb51721c7089be298591bdd426a15b4fbe2a
        // 1194bd4526a1dd1da28281372ab8a4f541532e9e0e0a083c782116da52c9dab0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
