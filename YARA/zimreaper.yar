rule zimreaper
{
    meta:
        description = "Auto-generated stub for zimreaper based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-24"
        version     = "1.0"
        source      = "OTX"
        family      = "zimreaper"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c010f64080b0b0997b362a8e6b9c618e
        // e3ce7d13a83716594787a12edf6cbeedc76b9a65
        // 98df604ecc57f884a2e6ce3266a0013ad64455cac48442c2312cfa4765007aaf
        // 1517b3caa495f6c4e832df9c75fc94667e3c233773f7fa4e056d5e30e5ead760
        // 60db9abae75cd8ccc49dd7ea5feb41677566dcd442f12ebc5745ffd2810fb874
        // b1f5beb1175fc5c7d1806a2f0d900eb124c54f0286c5c52b66eea7a6633adb1d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
