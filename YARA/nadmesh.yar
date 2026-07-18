rule nadmesh
{
    meta:
        description = "Auto-generated stub for nadmesh based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-18"
        version     = "1.0"
        source      = "OTX"
        family      = "nadmesh"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ca024acead8f54cfe5b07ac4bdf7fcea
        // 31c69b3e12936abca770d430066f379ec1d997ec
        // fc4109f5dd1d30b65dd60e57dc639ac1d313bfa5241e36e61fbc4aabc1cda482

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
