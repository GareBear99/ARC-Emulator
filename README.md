# ARC-Emulator

<p align="center">
  <img src="assets/brand/arc-emulator-logo.svg" alt="ARC-Emulator logo" width="220"/>
</p>


**ARC-Emulator** is a legally clean, binary-first emulator framework for preservation, deterministic replay, save-state proof, input timelines, and ARC-native game/session memory.

Roadmap order:

1. **N64**
2. **GameCube**
3. **PS2**
4. **PSP**

ARC-Emulator is not marketed as a flawless emulator today. It is a professional foundation for building emulator cores with verifiable binary state, cryptographic receipts, deterministic replay plans, and ARC-Apache compatibility.

## What makes it different

Traditional emulators focus on running games. ARC-Emulator adds an ARC proof layer:

```text
ROM/disc image -> binary manifest -> session receipt
runtime state  -> binary save-state object -> Merkle/checkpoint proof
input timeline -> deterministic replay stream -> verification receipt
AV capture     -> StreamMemory timeline -> ARC-native session memory
```

## Current v0.1.0 capability

- CLI shell
- ROM/disc identifier
- binary packer
- SHA-256 and Merkle proof utilities
- manifest and receipt generation
- input timeline format
- save-state container format
- replay plan format
- N64, GameCube, PS2, and PSP roadmap modules
- legal preservation policy
- test suite and GitHub Actions workflow

It does **not** yet emulate commercial games. The first executable target is a legally clean N64/homebrew/test-ROM development core.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI

```bash
arc-emulator doctor
arc-emulator identify ./game.z64
arc-emulator pack ./game.z64 --store .arc_emulator_store
arc-emulator create-session --system n64 --title "test session"
arc-emulator save-state --session SESSION_ID --system n64 --state-file ./state.bin
arc-emulator verify-state ./state.arcstate.json
arc-emulator replay-plan --session SESSION_ID --system n64
arc-emulator smoke
```

## Legal boundary

ARC-Emulator does not provide ROMs, ISOs, BIOS files, firmware dumps, copyrighted game assets, keys, or decryption material.

Use it only with legally owned and legally dumped software, homebrew, public-domain test ROMs, or your own development builds.

## ARC ecosystem fit

```text
ARC-Apache      -> binary object store, manifests, receipts
ARC-Core        -> authority registration and policy layer
StreamMemory    -> visual/audio gameplay session memory
SURE            -> seeded deterministic reconstruction recipes
Arc-RAR         -> portable replay/save/archive bundles
Proto-Synth     -> visual emulator/session graph
LLMBuilder      -> verified gameplay dataset lineage
Language Module -> metadata, labels, titles, OCR/transcript links later
```

> Binary-first cryptographic emulator framework for deterministic replay, preservation, and ARC-native game memory.
