rule sloppyrat
{
    meta:
        description = "Auto-generated stub for sloppyrat based on 31 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-12"
        version     = "1.0"
        source      = "OTX"
        family      = "sloppyrat"
        hash_count  = "31"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1c15653d8428e69ff2cadf3a3a1f506f
        // 5731f763100773be35669757b8accc95
        // 5966d07d4cb3a9241fe4df0ad70ad665
        // f52464f721825936cd1338eac49ece10
        // 3f90411b3a3ed8cbe079db215a9bf68b9017a9fc
        // 70e1412bd5ff942cb85233764968349e0181683e
        // 7b52af88cbd890b1d547729adf40b8d94c7cace6
        // d5435129570d9656dc7d9f6578a291d173025e4d
        // 00c116e498799dc831c8aeb602349296c4b9325535d674fe2b6e2e091878dcec
        // 1439990ff65364a0f608a322aa3a493bc1683cb5fc30cffc44948da29623fffd
        // 2f3d95de716f330fad2330d8787ebdbecb3322453bdc41b2113427f9f92d32d2
        // 3a8994928f512fffcb32e117ac45e0ee093541d99a9dba5f69a264f7f3054b19
        // 466f9b8dce77b3a026fe4f833aa4949784fb854bea4137e52609e857d439dec8
        // 4ecb2d06510dfee1b67f5d9a68c60f6d09ddb5be36cc1766a41d77c5b89d3a56
        // 518cd57a303ff7ac2b5c4c8439aa5bcbf9a287d4653de7b76051bde73a94d064
        // 607212cfe73c5c84b2dd95b2c0ff37a47f4c8aad08e6d5cbb7c19a62c6b765f9
        // 680c3a9f5fdddfcc34856c7a67d21bbdd2b47d70bdfb829ff59cfa0e3bc72d21
        // 6d50bb50d4e7d6ac36ca6d2761f382be8e1ddbebf3cdf4733cf989ba291f9013
        // 7bb025b426ae6ccbc170fbca58634b8dd77a61447e48dabe9c2e2fb0d339d8b7
        // 8774533134d9d1514106c4090a0c5bccab4550facdcfe03f4e02b9764343a990
        // 93273ea09bd9df881a594db8cfe1b1bbc54f40f623f44427278ae96fb9b46490
        // 971f25f84be88c4fd304d555b5e3da12f6b368e4b9ba0943961ff21ba6fa4d4d
        // 9f84cfcf988530941555d1cb7780a091743cf567396201eff7731f5475768f9a
        // a13fcbb0870f2fabb7e0a8c757ee3b763bd4a4b0cdf59eeff981d8e307fcf316
        // af4c426b8c4b3b4957875206948eedae09b670f349f2ffb70df7b7a6b06cd588
        // bdcf8fe230e23692b658b62b6547374e2234f2a497b19d26637018a1839e6dfd
        // c0ef62a2d5ca11c2eedad3561d5d1d8b6e9847aa6b8613493e5bc233ece3d189
        // cb9930d0cde5bf8e8a7ad08fe2c60b937c7beaf9ab51b03191dfcaba40b7b189
        // eaa52d2d6d4daf29157e8e813247fb2e92797324230ee42c79f7861b2f5c341d
        // f534a957edec74d69081665309311b791b6d11a3221fffa67744812d73ad98eb
        // ff142fc192daa2a83bc565e5b38ebbe05561f3a19c7fc2d08e38c97e1986bbc5

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
