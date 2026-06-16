rule win_asyncrat
{
    meta:
        description = "Auto-generated stub for win.asyncrat based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.asyncrat"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c0d896e94c4dd8b64f400d16ec3cb59f3c51fc940d06241a028d0204d0407a94

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
