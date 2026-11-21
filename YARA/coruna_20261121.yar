rule coruna_20261121
{
    meta:
        description = "Auto-generated stub for coruna based on 22 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-21"
        version     = "1.0"
        source      = "OTX"
        family      = "coruna"
        hash_count  = "22"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 57620206d62079baad0e57e6d9ec93120c0f5247
        // 14669ca3b1519ba2a8f40be287f646d4d7593eb0
        // ea3da0cfb0a5bdb8c440dd4a963f94cbd39d9e44
        // d11d34e4d96a4c0539e441d861c5783db8a1c6e9
        // 57cb8c6431c5efe203f5bfa5a1a83f705cb350b8
        // e3b6ba10484875fabaed84076774a54b87752b8a
        // 171a7da1934de9e0efb9c1645f4575f88e482873
        // 17480ecc0120292fb6b8b19f2fa134385dcfd0fd
        // 29b874a9a6cc9fa9d487b31144e130827bf941bb
        // 3bc0f6865c0476c0a98a76cb9924d6b3972df591
        // 3fd66b32c44150acff3dcb80f86c759574148ed5
        // 46ecd515ac9e99ef0603063db39303a0fd849632
        // 477db22c8e27d5a7bd72ca8e4bc502bdca6d0aba
        // 4a75f0551eba446b4fa35127024a84b71d9688d6
        // 6beef463953ff422511395b79735ec990bed65f4
        // 8c4451cf1258f9a8d6a8af27864f111fd69a0e99
        // 91b278ddb2aec817b10c1535e0963da74f9b8eeb
        // 9db8a84aa7caa5665f522873f49293e8eebccd5c
        // b586c88246144bc7975ad4e27ec6d62716bf34ea
        // bef10a7c014b826e9dd645984e80baf313c1635f
        // f6377d5d458183d41c5fd99661c5a306b42c6255
        // ff4f3cb4711fb364b52de5ab04a8f83140466f89

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
