rule purerat
{
    meta:
        description = "Auto-generated stub for purerat based on 27 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-29"
        version     = "1.0"
        source      = "OTX"
        family      = "purerat"
        hash_count  = "27"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 82699276b0f59a2304120a6baaf64a6b
        // 5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946
        // 87903559afa09a0dfe251598c14e58124bddde1d
        // 1fdea279cb8c9217487ac4c86ae9316c
        // 2e05d97ed7bfabea8f7370ba627e0705ec2c0fbf3974b39437e9d95d45d1a76d
        // 719f689b34f47be8ca105ce8484948474dafde0e106bab599e4a89326070c3d0
        // 05e27e1a0ed75c32e896c5d0261bb077
        // 6624eb2d2637338c82b5325141f1f75179a74660
        // af4ee79582992e348a8739579da478d50daccbaa6ec97420311916a2ac0fc503
        // e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0
        // c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8
        // 8cd271f946d84423c554992eb0176be395cdd7bf6179efe1822759d019c94f34
        // eb20fb4e1de2844717270e600af05abac06b359be711eabf14a3d91bfbf966e6
        // ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa
        // 9e54486f204d8c9ff9c539c5b2119b79a6da21e3dfdb7f51ee8ebba62f851174
        // 1b5cf526a28bae9283acf91b2c0ccae3163d24706e40d9a0aea38c4b79e65d36
        // 567fc6e35bb45a6ecf5d870e454c813613032078a5ba01fcd374544930598703
        // aee2aefbc73dbf5f65e455ef18e74e158290e21803bf3dd64a05d087bfaceb18
        // afd31f096c93776888454e1321654477cfd97eb0c6a75bea624d8f7d891e0a61
        // 5331793d7c89907eeff77081d021d10d
        // 6d90494c1119bb8cc67a85a9ac9aeaca
        // 79435213ab241b13a9d8da354c088868
        // e951e6e4ef4a2696c69306693abd4a0e
        // 1f655ff488320c589cb50f8ffe2701f7208999fe
        // 6232326f3da33c340c57e7370e038085d5f86d88
        // f58f4bc7e421bb2e1117c22a8acf120de388d442
        // 1be5cfb6b0e2ed8cf2c63365213f8a58f1a75e93899e7018acfa6b3484e8baa0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
