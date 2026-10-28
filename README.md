# XnuPrelink

XNU kernelcache prelink and ABI inspection.

used by the kernel build and the sheng payload step.

Build and interface details: [documentation](https://unixnu.com/drivers/xnu-prelink). Component sources and dependencies: [catalog](https://unixnu.com/reference/components).

`emit_prelink.py` selects the fileset path for an `MH_FILESET` input. It
generates a function/data pairing with `fileset_match.py`, or reads one from
`--fileset-map FILE`. Both input hashes must match before an existing map can
be reused. The ordinary ARM64 prelink interface remains available.

The fileset emitter places the collection root at the native kernel's link
address, marks the copied kernel as a fileset member, rebases metadata and
keeps only the selected roots and their dependencies in the fileset index.
The legacy `--slide` value does not apply to filesets. Rebuilt chains use
virtual offsets, including across native BSS gaps.

`fileset_layout.py` places native segments in space freed by the replaced
kernel and omitted entries. Code follows retained kext code; constants and
data precede their kext ranges as required by XNU's `arm_vm_init`.
`fileset_segmented.py` applies native split-segment v2 records, rebuilds root
fixups and function starts, and recomputes corecrypto's HMAC over relocated
code. Segment collisions and unsupported relocation kinds stop emission.
The native input executable is unchanged.

Maps carry a matcher version as well as input hashes. The integrated CLI
regenerates outdated caches. Reviewed symbol anchors in `fixtures/` include
function hashes and identification evidence. Other matches use code, data
operands and identified vtables. A `.cold` error path is not substituted for
its parent function. Link order alone does not bind ambiguous functions.
The comparison recognizes complete compiler-inserted PAC failure checks and
preserves branch geometry when comparing bodies. Native code keeps those checks.
Both emission entry points reject maps produced by outdated matching code.
`emit_prelink.py --fileset-reference FILE` accepts a symbol-bearing comparison
kernel, such as a RELEASE build with LTO. Unique code matches may supply an
unambiguous symbol name in the actual native kernel. Reference addresses are
never emitted; compiler-generated names and graph-only guesses do not transfer.
The map records the comparison image hash. The standalone matcher calls this
option `--reference-kernel FILE`.

Missing mappings stop output and are listed in the JSON report beside the
requested image. `--allow-missing` explicitly permits an experimental image
with unresolved references. Pairings are inferred from stripped code;
successful emission and structural checks do not establish ABI or boot
compatibility.

In the UniXNU build driver, `unixnu kernel --skip-prelink` builds and stages
the native executable as `kernel.macho`. `unixnu prelink --skip-prelink`
stages an existing build. This path copies the native bytes unchanged and
does not fetch a kernelcache or add its kexts. Its adjacent JSON record marks
the output as `native-only`; payload arguments and loader support are separate.

The lower-level `fileset_emit.py` accepts `--map FILE`, `--output FILE`,
`--report FILE` and repeated `--root BUNDLE_ID` arguments. Run host regressions
with `python3 -m unittest discover -p 'test_*.py'`.
