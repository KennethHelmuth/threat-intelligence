rule win_stealc_20260808
{
    meta:
        description = "Auto-generated stub for win.stealc based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-08"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 3082ed63bb7d87f051c6a167d371b20b
        // 212199a413252df5ad9be87d8070083d74a9f3e7919b3c005db2ed7fe6793343
        // 6d3ec0d0e31dc8d2e52d545f317a88fa
        // 5c113804b804fb934afe84965e69a2bd912cef31203b2e4f367d8986b8783c93
        // 652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9
        // e79ad54bd794375224a5d76d56f3180b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
