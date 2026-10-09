rule poellm
{
    meta:
        description = "Auto-generated stub for poellm based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-09"
        version     = "1.0"
        source      = "OTX"
        family      = "poellm"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6fab94577364beec314afae3b082dd680933f08a8349b9f35b92667e8231b501
        // acaf0ec9d31646c2fb59f84f35e6a174
        // be2ffcc4591e527c48d98a53b66521b93671975e
        // 350a99830b80b5600d3a2757fa996155579ef9d0c53de95f0299f64d280b9bb1
        // f706aba0d150db2d8f385cbbbb6a6d4fe590a5d184f29e5b1b05fcc4c2cd0932

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
