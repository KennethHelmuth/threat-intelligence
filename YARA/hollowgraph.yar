rule hollowgraph
{
    meta:
        description = "Auto-generated stub for hollowgraph based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-22"
        version     = "1.0"
        source      = "OTX"
        family      = "hollowgraph"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 315bdba98c6fe863d39f6afccc727e17d5aea63bf21259444fa988cae56d61c1
        // 1573e125197ec77d8e9930c611ba2802ee59e19629396b5e99b426b46c53bd25
        // 75e51774b8f79e5f256eaae639635f911b3e744d4774fd6068dd980255621509
        // b3d0f6e4e3be395fd7cf9e8101c89963d77216578cbb117a6ac9bc3564485eff
        // f3f3006f8304788251b153d53b305322b8acab0c66ec816b8d9f101bcc851da3

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
