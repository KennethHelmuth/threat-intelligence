rule harborwatch_agent
{
    meta:
        description = "Auto-generated stub for harborwatch_agent based on 7 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-10"
        version     = "1.0"
        source      = "OTX"
        family      = "harborwatch_agent"
        hash_count  = "7"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 09c121225fe254676a27c21943506714
        // 33760b2aa86deea5805e647197c34ef5
        // 9abebe5a34eefb80db12bf8d51bfe7f7
        // b31f62e1d3b28808daad3ec5efa5df54ae56898d
        // 3a87cab1e8c6868a7939eb422f1851ecc746405cda6b3d3502b9d8eedc360898
        // 5f7bb80bf85c1fae7413eb534cc2f022402c8753f75666525adb1dc85a677f4c
        // cf94ff2ecc4f3157704c9cfed5e446c405e7729141019045cb05ef6ffad122d5

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
