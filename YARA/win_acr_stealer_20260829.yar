rule win_acr_stealer_20260829
{
    meta:
        description = "Auto-generated stub for win.acr_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.acr_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 105195dfdfbfdce7cf13f50d92bba761eba5bc22c31000109a67708f61474e12
        // 8be48ea27f6cd6b2ec2ef3be4977322d
        // 98f00e36daaf4c4bae91031d4b53ea9b
        // 46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
