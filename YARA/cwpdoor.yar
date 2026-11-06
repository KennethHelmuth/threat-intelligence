rule cwpdoor
{
    meta:
        description = "Auto-generated stub for cwpdoor based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-06"
        version     = "1.0"
        source      = "OTX"
        family      = "cwpdoor"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 965aea67fb40de1bab5169ada993349f
        // d3f4e95113d49ab3991b45e457bda75b
        // e505d4ffa21cf494a5dc2d7c8f4f1236

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
