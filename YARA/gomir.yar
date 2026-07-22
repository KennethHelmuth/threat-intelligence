rule gomir
{
    meta:
        description = "Auto-generated stub for gomir based on 14 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-22"
        version     = "1.0"
        source      = "OTX"
        family      = "gomir"
        hash_count  = "14"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 84e9b066bebd49036b7fc71b5f5f8d83
        // a452a860f973c7a43ea804c17e9427d2
        // aa61e76255a6e13313439655bc02bdf5
        // b1c72139f2cdd9419562369fc6ced4fc
        // bf215181b5140522137b3d4f6b73544a
        // c2e37232556357944a04edf1dec3934b
        // ca98a51cebdc802d255030b4baa44ca0
        // dff787bce68c7653495f153c0534cb96
        // e6c6fa32da47d9341b778bfa424abb4c
        // e911f8f7c49476806ada37f3ebb7a28a
        // 3fb6111490cac9f5c4b34f9fed459f01c10d2314
        // f3ed0bcc692555fea83c6556abaa5dc2b91bcb38
        // 01b1c767f62e48efeb86410fd014fed4295ccb084bfcd6d5b9197638b615a648
        // 073d9dd98a9ca3cd03901c31ba57811a1632e316923022640670ce00622cd8a9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
