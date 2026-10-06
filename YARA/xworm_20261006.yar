rule xworm_20261006
{
    meta:
        description = "Auto-generated stub for xworm based on 23 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-06"
        version     = "1.0"
        source      = "OTX"
        family      = "xworm"
        hash_count  = "23"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ce02802067934e0eb072f69bf6427bf6
        // a06eb79f0ebe4a6999bcc71a2227d8e3
        // 5f63fe34d77b1eff07a9eef9d7ca1df2537aa90cb1d3fc2e215086d2397313c5
        // 0718eaa1978c571ddfc9a8c53fdc77eb3b32688831aa3971bd316ca944daacda
        // 91dff3071d68678e4c1f67675f785372244e9c5952d7a8a100a476323d9d4627
        // 2b5f0c927f5436d8c04d58bb8c9fba470cbbf4ce23eacf2d65e336ca2bb59d97
        // 2d28e503d95b6fa5df5b56ea77fdca3a
        // 3a17c971d67659cfb590bd97f131039c
        // 7c2b5d3b7535da03eeecb3dacafef353
        // c99ed89d7e53d4296aad646b7b19ac96
        // d63a77050451cdf76dc317b358d62f84
        // fb6e940e3e6ed598a9953950bc4819f7
        // 2af9f0e9421d3ffcbe4923eea87720c760ca41cd
        // 49b21cec222b473d2d2ca942d94aec4c02eb6039
        // 5e6cb6842c63b751a04e14a4a4f9602d5c7bf337
        // 94b07e3f93813ec17fed88f5a2aba44b22962e5d
        // 965e01a5974dec5f60461c48550f2b7c314c7cee
        // be312034d50a5e2cf8e25bd4011ad2dbcb876910
        // 3575a22ba626d0103e8fa5cda194e972e8ec0aa29aa9e9eceb4c48819963bad6
        // 3e3f0f03a52304570aaf18d4536e8be8a3577e68a198edc53e5877283c18ea5d
        // 4d403644d7520429283d7e1e4477971fe0b5a418d5e1341f9f12f8f1e84480ee
        // 9a8dc848fd13565eea98b5e5e9ef222bf2aa9b83df316813ebaff46c1f28c4d3
        // d15f8b15696bf2118bf81cf9656f28a6bc6992731956f2e070ce0f033fdd2ef3

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
