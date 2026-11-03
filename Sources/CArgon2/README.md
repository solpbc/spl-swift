# CArgon2

The Argon2 reference implementation, unmodified, from
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) at commit
`f57e61e19229e23c4445b85494dbf7c07de721cb` (2021-06-25), under CC0 1.0 or Apache-2.0 ([LICENSE](LICENSE)).

Only the portable sources `SPLMark` needs are here. `opt.c`, the command-line tool, the benchmarks and the
test programs are left out, and `ARGON2_NO_THREADS` compiles the thread pool out, because the mark runs one
lane. Do not edit these files: replace them from upstream and rerun the mark vectors.
