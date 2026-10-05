# SDK History Provenance

This repository was extracted from the `lethenymous-sdk/` subtree of the
`lethenymous/zkcpmm` repository in a temporary migration clone. The extraction
used `git filter-branch --subdirectory-filter lethenymous-sdk --prune-empty`.
The source point was the last monorepo commit containing the complete SDK,
`7c3abbb7889f030c512763880c5b3fabdeb8d2fd`. The later monorepo separation
commit `f3db0cfb128d92f103694fa8b19ad69cdd93efad` removes that subtree and is
not an SDK development change, so it is not represented as an empty standalone
commit.

Filtering changes commit tree and parent hashes. It does not create synthetic
development commits; the extracted commits retain the original author
identities, author dates, committer identities, committer dates, messages, and
SDK changes.

| Original monorepo commit | Standalone commit | Subject |
| --- | --- | --- |
| `df808cdab3f7076cb6f88e0b00ad5f4164f2abe0` | `5612e1970a83c6e8f32f12c69626dd67666f9412` | Remediate SDK release security findings |
| `e4089ba81d201fa6dbb6a287126edf08e1a61141` | `0c1c09e618604432149e7f92773ac69343c79de3` | Harden incremental Merkle synchronization |
| `e2b4291a8e48cadd402e19162cb0b1de6405d819` | `1d4a2328a9649f89d47e28a3e0cfbebdf777bbe8` | Finalize SDK provenance evidence |
| `7c3abbb7889f030c512763880c5b3fabdeb8d2fd` | `bae424d076e59459eb34f9c489046cc6146e712d` | Finalize SDK Private Send release candidate |
