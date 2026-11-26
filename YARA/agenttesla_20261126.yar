rule agenttesla_20261126
{
    meta:
        description = "Auto-generated stub for agenttesla based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-26"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "agenttesla"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1
        // eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa
        // 7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768
        // c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0
        // cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
