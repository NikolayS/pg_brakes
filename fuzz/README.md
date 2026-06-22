# pg_bumpers fuzzing — hostile parse loops (SPEC §4)

This crate fuzzes the two **untrusted parse loops** the proxy sits on:

| Target            | Under test                                  | Invariant |
|-------------------|---------------------------------------------|-----------|
| `frontend_decode` | `FrontendMessage::decode(tag, body)`        | arbitrary bytes → **never panic**; malformed → `ProtocolError` (fail-closed) |
| `backend_decode`  | `BackendMessage::decode(tag, body)`         | arbitrary bytes → **never panic**; attacker-declared counts → no unbounded alloc / crash |
| `classifier`      | `classify` / `classify_with_reason(&str)`   | arbitrary SQL → **never panic**; a write / DDL / stacked statement must **NEVER** classify as a safe single `Read` |

`fuzz/` is **deliberately NOT a member of the main Cargo workspace** (it has its
own empty `[workspace]` table). The fast CI job (`fmt`/`clippy`/`build`/`test`/
`deny` on Rust **1.90.0**) never compiles libFuzzer; only the dedicated fuzz CI
job installs a **nightly** toolchain + `cargo-fuzz`.

## Run locally

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# Short, time-boxed run (what CI does on PRs — ~60s/target):
cargo +nightly fuzz run frontend_decode -- -max_total_time=60
cargo +nightly fuzz run backend_decode  -- -max_total_time=60
cargo +nightly fuzz run classifier      -- -max_total_time=60
```

A crash drops a reproducer under `fuzz/artifacts/<target>/`; re-run it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

## Longer / nightly campaigns

CI runs a short 60s smoke per target on every PR (enough to catch regressions
without slowing the merge loop). For deeper coverage, run a longer campaign
out-of-band, e.g. nightly:

```sh
cargo +nightly fuzz run classifier -- -max_total_time=900   # 15 min
```

and commit any discovered reproducer into `fuzz/corpus/<target>/` so it becomes
a permanent regression seed.

## Proving the teeth

The `classifier` target asserts the **fail-closed safety invariant** directly:
it stacks a known write (`; DROP TABLE …`, `; UPDATE …`, …) onto the fuzzer's
text and asserts the result is never `Read`. If the classifier were broken to
treat a `DROP` as a safe read, this target fails within seconds. Likewise,
adding a `panic!` to either decoder makes its target fail immediately. CI
demonstrates this (see PR #42 evidence).
