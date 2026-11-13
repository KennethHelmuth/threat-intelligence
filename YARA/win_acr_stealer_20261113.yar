rule win_acr_stealer_20261113
{
    meta:
        description = "Auto-generated stub for win.acr_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.acr_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ca52a8272ad07c302836fe9c1166d0205ba7eda2da542c2645aa45c137fde2cf
        // 2991e31ba14d67d9fdf41557f932742a
        // 3e8471c791f6b1154025406361a77810
        // 10b84dd212e90e91c34bb62ad2b2e943f2324b5c5d24af767802415c54a56028

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
