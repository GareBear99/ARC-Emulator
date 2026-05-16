# ARC-Emulator Architecture

ARC-Emulator separates the proof plane from console cores.

```text
media file -> binary chunks -> chunk hashes -> Merkle root -> manifest hash -> receipt -> optional ARC-Core registration
```

Console order: N64 -> GameCube -> PS2 -> PSP.
