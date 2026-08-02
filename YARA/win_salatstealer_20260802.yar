rule win_salatstealer_20260802
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-02"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e5d203aa2c95d96736d44cb35fff96fe
        // cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10
        // a536b532e5ebaa0617688a42b5543b0a7144817e0dc12020826d74cc9b22c5a1
        // 63d711bd0e3f33911c28fa2fd0d9fb76

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
