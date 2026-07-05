rule win_zloader
{
    meta:
        description = "Auto-generated stub for win.zloader based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.zloader"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface
        // dcfbe94f7ead20bb942b06ecb67937fd

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
