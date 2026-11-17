rule nodelinkrat
{
    meta:
        description = "Auto-generated stub for nodelinkrat based on 13 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-17"
        version     = "1.0"
        source      = "OTX"
        family      = "nodelinkrat"
        hash_count  = "13"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 12345678901234567890123456789012
        // 7575d230350299cfde0c4f993d761333
        // cbcb66b530fb4f03d7dc9d55271b2ce4
        // ef317291bf88651666133abe84f115f0
        // 6985f297c03520a5852734a385322d8d
        // a151531b792b1df1eec8d3a6a8e1ded5
        // a15df586bf29e7c1a5db64d603cee382
        // 63ac4cc6fa997a32b25f447b5291293bba91cba9
        // 70f643348787e05e1cdee5103b37205c8bd93080
        // cc6b492eeb36868ad0dece02fbd64ddb58fbcbf3
        // 2c6055144868467157075d7a14be47649e00d2d44fb19d816309b132ce367ebe
        // 4be927bf8c273aab1e11705a4964221d669a9ef9ef03851cf53415a6a3297183
        // c81bf074960f5abba48ed21ce40e775924e9d8ea37d78825a1faf1adf8525a88

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
