rule xworm
{
    meta:
        description = "Auto-generated stub for xworm based on 22 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-02"
        version     = "1.0"
        source      = "OTX"
        family      = "xworm"
        hash_count  = "22"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 599f80a79efdc584c70f4f763c663b06d432393c
        // 51fdd83b3737add7f3832bd0ad0b56863c0a8f7cf9bcc16fd787d1ae4b403ce6
        // 833368e3029a38a4f87207acd537070e
        // d2aa40cc53b40c6e76ac0677c4a54387b3f27ee94c85d9b2c3a3d66aeef92a66
        // 3b22605244dbace8f0c07c2c599f88c4b831bb07e9998b869a5da2759d27ceec
        // f0cfe3559bf988d4477a6ac2bcc6c025
        // 31f578c8d2d51bc91b7dfe4d663cb0ad079d5869
        // 6652cf491ed9992eb2f3af23e9641cd987096280
        // 0ef9f39b2685b42c78fc6859498b29bf
        // f139b4ca15feffb7a6633ec1a431c5c604b397576b56b5c863ae8fe4fa14db4f
        // 54e3e03c168899fe9e3ecea2c46b5359
        // cd382e301231bb1a86ad06e9d492dbfce6a43fab
        // 2214907e696bad85bde1d90c943ef66e413d7a5c6d7596ced25b74441200439a
        // 447e3a131e62bd33b1297739a7b959a92358a97f58554469044636a3c4f244e8
        // f25b2229715bd66e783ecde70843f01d
        // c23d24b2888d02998f7c0f6091ab2e69fbac4a3e
        // 6d4012e0dd3b56a3e52857734fa0d582cdf3c56f0e5decc8005c882d1d1c6ceb
        // c0db6ddd6222d02ad7490399d33c61ded0076f0037409dc8498924458646d78a
        // 08cbd834a5bb5f402d771003f437c206a0a67c6e
        // 419df93671ff0eedc118a641bab30584f84d16a6
        // 9bd6d2a99a5a63805578d775fdedc7dc2ad765fa
        // ea259f3e37f87ddb3d619a7fecb072471af97c3a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
