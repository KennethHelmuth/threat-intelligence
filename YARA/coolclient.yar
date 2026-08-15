rule coolclient
{
    meta:
        description = "Auto-generated stub for coolclient based on 7 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-15"
        version     = "1.0"
        source      = "OTX"
        family      = "coolclient"
        hash_count  = "7"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f518d8e5fe70d9090f6280c68a95998f
        // 2d7c8780e97409770a9d4f31c66c9d63
        // 9460e150e1981d5c165043520c5c12fe
        // 9717f005c5fb98e08d2ad983d88f94ee
        // eb79558b037669792652a816e2c669de
        // b813c4d9be3ba88159f1f83ce805f8b730b38dde
        // ee72ae4cc869affddab11647e95bab9c5691c9fc76dcb4b31650ff504da29156

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
