rule win_salatstealer_20260626
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 8 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "8"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 104f3ba9a4884a153696833fb7d90c24
        // 13a3e7f3955eb52b9e281f191cbcb8cfd7a7c21f371df21246ce5106070541c9
        // 352fed139c6838c4ccc695a26ccebfd5
        // 3972f0b20671837938996ebf0e6dba5e36a8dd3dcd9cf72ade6300506e670380
        // 0cc9c48a044cdfb621b3c24427e622c6
        // 1737899af08da74b07395f82cff64b0c6c8c0eb30ee9b3b5b5eb652874cd0112
        // a9ab1790f4c6691fa91373bca0812a52
        // 46ea5e72b0203fe4d9e2155a033f7bcd4582c12550d8ea9a112f7c03b24de347

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
