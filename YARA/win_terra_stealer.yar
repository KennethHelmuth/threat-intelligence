rule win_terra_stealer
{
    meta:
        description = "Auto-generated stub for win.terra_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.terra_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6435611106d0d7b3301229b9021a9908
        // 83928513bb5518e71704d089dedfe44d
        // 0d29741bb7161b12319909ecbbfb6029b08fe80c98fc8a93658ea14fededdfd9
        // bc7d5b9ae130f1b9c5a41517d56d9213950ef7f9b1ed78d9f33a4b2797d009e1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
