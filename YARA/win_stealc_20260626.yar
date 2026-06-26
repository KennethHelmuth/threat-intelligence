rule win_stealc_20260626
{
    meta:
        description = "Auto-generated stub for win.stealc based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 27988a7e5afee247366e8f560bd37e14
        // faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe
        // 07cc22c1db2b39a7fc3058b02ec15225b2945e4866a9a0e84b8f73672ae9bcd7
        // a61025e3511cf9700a38e681a1fcdc81

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
