# Analysis tools

- `fingerprints.py`: relocation-insensitive function fingerprints used by the module to decide which patches are safe on a
  given game build. `fingerprints-3.0.5339.json` holds the known-good values.
- `plt_scan_portable.py`: offline reference of the on-device PLT-bypass scan (program headers, PLT stub pattern,
  `.eh_frame_hdr` ranges); compares against a list built with section headers.
- `plt_bypass_build.py`: the original offline site-list builder (needs the game's `libtq.so` and pyelftools).
- `abbox_fast.py`: the hand-written ARM64 `ABBox::GetIntersection` and its equivalence test against the original code in
  unicorn (needs `libtq.so`, keystone, unicorn, numpy).
- `getend_stub.py`, `destroy_stub.py`: small assembly wrappers used by the agent/module.

None of these files contain game code; scripts that need `libtq.so` read it from your own installed copy.
