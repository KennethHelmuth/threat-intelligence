rule win_urlzone
{
    meta:
        description = "Auto-generated stub for win.urlzone based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.urlzone"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c2b46142bfd7edbb48349bebd24d78ef7b3d43e8ce5052c422c9990c789ff839

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
