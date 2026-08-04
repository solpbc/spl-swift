<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# SPL authority definition bundle

`bundle/` is a read-only, byte-identical copy of the five-file pair-link
definition bundle from authority commit `ddfe13b2abce2fd40acbe2e18d0551727e7ef757`.
`bundle/manifest.json` is authoritative for the payload inventory and digests;
`adoption.json` records this consumer's selected authority material.

## Re-vendor

1. Check out the intended authority commit in a clean `solpbc/spl` worktree.
2. Copy exactly `manifest.json`, `definition.json`, `definition.schema.json`,
   `vectors.json`, and `vectors.schema.json` from `proto/definition/bundle/`.
3. Verify the copied payload digests against the authority manifest.
4. Update `adoption.json` with the authority metadata and ordered payload list.
5. Update the conformance-test constants, review the vendored diff, and run the
   repository gates.

The SPDX header on this README covers the corpus directory. The authority JSON
files cannot be annotated or reformatted without breaking byte identity.
