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

## zk-kit.circom binary Merkle root

`circuits/merces/merces/dependencies/merkle_root_4.circom` is adapted from
[zk-kit.circom's binary Merkle root](https://github.com/zk-kit/zk-kit.circom/blob/main/packages/binary-merkle-root/src/binary-merkle-root.circom).
The original is licensed under the MIT License:

> MIT License
>
> Copyright (c) 2024 Ethereum Foundation
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction,
> including without limitation the rights to use, copy, modify, merge, publish, distribute,
> sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
> NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
> OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
