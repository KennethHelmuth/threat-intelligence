rule xworm_20261126
{
    meta:
        description = "Auto-generated stub for xworm based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-26"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "xworm"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa
        // 27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57
        // 4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
