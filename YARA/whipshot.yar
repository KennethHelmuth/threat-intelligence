rule whipshot
{
    meta:
        description = "Auto-generated stub for whipshot based on 10 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-21"
        version     = "1.0"
        source      = "OTX"
        family      = "whipshot"
        hash_count  = "10"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // b0871d353743fb2736f3b5ecf178788a
        // b215276fe51063cf2e4d38bbffddb112
        // 30b71217b1e8d5b13394d4ffe3b11029d14adfa4
        // c6e443496337f0fab189bbbdfe91a102f1d56678
        // 56a892d80096a9db4ca473a9c3109729c60a5ba901d6ba65948bdb1f4a6fb186
        // 6774bfed99da38cec82e721de4bd64a67db7840efadcc71e7df02eb6f0a03c44
        // 8e8b9532ce40eacfe1b4cf2b11241878b70b910aabd90b453b1460df19b51a4d
        // a0ba4e1ad622d9c3d950b4156d4430812d05bee216ab22c3804a9f7a80535556
        // eaf0086237879bbaac00a5874c0e2ff84deede1ba10e6b706e2288fd3a31cdde
        // ffe052fc50271e7739d458b155df790438776032bfd125b974735e1dd9c0b138

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
