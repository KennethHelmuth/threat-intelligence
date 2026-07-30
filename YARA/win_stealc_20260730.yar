rule win_stealc_20260730
{
    meta:
        description = "Auto-generated stub for win.stealc based on 36 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-30"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "36"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 740898b58e04118c41b698eea2c74e52
        // 6c31dfcd522d65460e749941d675c714
        // 0c16963f43604246e81f006d1f7df0a7258b36b929252c1502d92fea573d86aa
        // c200f2497e8169897a1f0569e720331faf5f2fbc50530614641d612b4488797c
        // 375f8a4ff4eafe485b210a9ffb6a84bdbdb9c52ae602293ddae53717935e8daa
        // 88fa7d9c846fd17986f8d0143cb3ca3a
        // b1d3605941588587ac6927b78bded977
        // 61ab1d22949eac0582e989ae065ec4caee9ac99998276317edda96735cd311fb
        // a8480ece517b8367ca8418d7888f410d
        // d1b8f36f0654d83e8f85fc828ccd8beb
        // 99cd8530772b5bb986883ebfd09410bfd5328581a3e993472826eda78d6e3405
        // 21aa4b32defa0fa0aea3e28559ee8fd8
        // 39e07fb60fbf206b06d1b5b2b74848d9d393c6bd66fd11e003436cd7ee6b5788
        // 7072509bfed6050e7f498f78adbb2fa8dd6b3ffb5ac71c2a3dff942bd484b413
        // 40d291a45b171ed64df46347ff3aecd1
        // cea15fe7edd6b1b26f4326901781c16034ebe195cdb89ede2338e91c1d7ce6ac
        // 13b4f73885f424f73207481d097109fa
        // 16efe20ecbe454a3390e05e1641c91bbbf436a2ab1c830b76dc6c8a8b4843f14
        // 52f00e919a910e2445bcd4d35e896693
        // d1b360a94b3b6acd26d04e9b2cde1df1
        // 72ba37f28406579b8556ca03137e7c2c4bed79e5fc875e560c017f161840fa65
        // 798b6a521d6763f1b684f6d2a6c91e3eab92425dbd9265372a132aba1e213c5f
        // f901e1a138129e819f4759f30102e94a9987409f0978c9505c2d679d1a0880e2
        // 25774b9f2918cb30364298716f64b014
        // ee2169a39bff9da6e3152e80a13b0bd9dc1e55c3ab191ca387bf8ede1ebdcd8d
        // 9aefb5da315cf02ef084b88028f5cef1
        // 91b902474fed81407fd811fb273df070
        // 77857be5f099f715e7706217aae7dd42
        // ff1c3a2866f389f8ec2e4d57600446da4d131bad8ded341aa6619c0a0d35f752
        // b6bc55d2b6e281b5bbf84f589a2847544233ad4b7abd05f942f27cba26703b8b
        // 0121b38de05462d8e1ab8081f3d76f04
        // 8802527c317068b4b824d7bc1843dee0e52e047c7fae4997d577c11349c1ef01
        // de5b161afabe16c6de6a329454fb6bc2503a016431881e1a152b1ab755afc447
        // 729f1552e401d7881dcf8b895a48565a
        // db05580a540923fc9018705a62224a36
        // a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
