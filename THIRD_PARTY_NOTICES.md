# Third-party notices

This file summarizes direct third-party components relevant to this repository. Transitive Rust
dependencies are audited by `cargo deny`.

## Circom

The `taceo-circom-mpc-compiler` crate links Rust packages from
[iden3/circom](https://github.com/iden3/circom) at commit
`ad44e915a12bb047b05745c2884aad9cc8326bc6`. Circom is licensed under the GNU General Public
License version 3. A copy is provided in [LICENSE-GPL-3.0](LICENSE-GPL-3.0).

## Circom circuit and proving tools

- [circomlib 2.0.5](https://github.com/iden3/circomlib) — GPL-3.0; installed as a test-circuit
  dependency and not vendored in this repository.
- [snarkjs 0.7.5](https://github.com/iden3/snarkjs) — GPL-3.0; used as a development and test tool
  and not linked into the Rust crates.
- [@taceo/circom-lib 0.9.0](https://github.com/TaceoLabs/taceo-circom-lib) — MIT; installed as a
  test-circuit dependency and not vendored in this repository.
