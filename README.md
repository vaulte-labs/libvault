# libvault

> **[Vaulte](https://vaulte.caeser.workers.dev) is the password manager for you and your agents.** The Mac
> app, browser extension and `vlt` CLI, with end-to-end encrypted sync across your devices, in one
> subscription. **[Get Vaulte →](https://vaulte.caeser.workers.dev)**

The core of [Vaulte](https://vaulte.caeser.workers.dev): a secrets vault whose keys are bound to the
device's secure hardware, and the broker that lets people and AI agents use those secrets without
an agent ever reading one.

- **No password to guess.** Items are encrypted with random keys, wrapped to each device's Secure
  Enclave with a P-256 + ML-KEM-1024 hybrid, so a stolen copy of the vault is useless, now and to a
  future quantum computer.
- **Agents use secrets, they don't read them.** One touch grants one agent one space for a bounded
  time. A loopback proxy swaps placeholders for real values only in credential headers to the hosts
  you allowed, an agent's browser is signed in by a separate one that hands back only cookies, and
  reading a value always takes a fresh touch.
- **Sync without a server.** Devices pair over Noise and exchange append-only, signed logs on the
  local network. Across networks, a relay joins them and only ever sees ciphertext.

Every interface, from the `vlt` CLI to the Mac app, browser extension and SDKs, is a thin client of
this library, so no interface can skip an approval.

## Status

Not yet released, and not audited by anyone outside the project. The format changed recently, and
the flows that need a person's touch on real hardware haven't been run again since. DESIGN.md lists
what is **tested**, **documented** and still **assumed**.

| Platform | Backend |
|---|---|
| macOS 26 or later, on a Mac with a Secure Enclave | Secure Enclave keys, approved with Touch ID or the login password |
| Elsewhere, including Linux | Software keys wrapped with Argon2id, approved with a passphrase every time. Written, never run outside macOS. |

## What's here

| | |
|---|---|
| `src/` | The library. Interfaces use `Client`, `Setup` and `run`, and nothing else reaches a secret. |
| `src/bin/lvd.rs` | `lvd`, the per-user broker that holds the keys. |
| `enclave/` | The Swift bridge to CryptoKit's Secure Enclave keys. |
| `tests/` | End-to-end flows that start the real broker and stand in for a person. |
| `fuzz/` | Fuzz targets for every parser of untrusted input. |

Features: `broker` (default) is everything that holds keys; leave it out in an interface that only
talks to `lvd`. `test-hooks` and `fuzz` let tests stand in for a person and reach parsers, and a
release build refuses to compile with either.

## Build and test

You need Rust (the version is pinned in `mise.toml`) and, on a Mac, Xcode 26 or its Command Line
Tools for `swiftc`.

```sh
cargo build --release --bin lvd       # the broker, in target/release
scripts/check.sh                      # format, Clippy, every test and the repository's rules
```

`scripts/check.sh` must pass before every commit. The deeper checks take longer and need extra tools:

```sh
scripts/fuzz.sh 600 5                 # every fuzz target for 600 s, 5 at a time (cargo-fuzz, nightly)
scripts/mutants.sh                    # breaks the security code and checks a test notices (cargo-mutants)
scripts/state_space.sh 4              # every sequence of roster changes and attacks, 4 deep
```

## Read more

- [DESIGN.md](DESIGN.md): the threat model, keys, records, broker, sync and what is still unverified.
- [FLOWS.md](FLOWS.md): every path a person or agent takes, and the test that drives it.
- [sdk-c](https://github.com/vaulte-labs/sdk-c) and [sdk-typescript](https://github.com/vaulte-labs/sdk-typescript):
  use Vaulte from C, Swift or TypeScript.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/vaulte-labs/.github/blob/main/CONTRIBUTING.md). Report a
vulnerability privately from the **Security** tab, as
[SECURITY.md](https://github.com/vaulte-labs/.github/blob/main/SECURITY.md) explains.

## License

[AGPL-3.0-only](LICENSE). If its terms don't suit you, a [commercial license](COMMERCIAL.md) is
available.
