# Changelog

## [0.1.0]

### ⛰️ Features


- Init from private repo - ([b6dbf20](https://github.com/TaceoLabs/circom-mpc-compiler/commit/b6dbf209632698d13048699322d0269ec662a0a8))

### 🚜 Refactor


- *(poseidon2)* Write requested results straight into a flat buffer via RequestPlan - ([f3b10c5](https://github.com/TaceoLabs/circom-mpc-compiler/commit/f3b10c5faeb25af97ea41c88cc13e245f76517a8))
- *(program)* Make every Program valid by construction - ([d312f93](https://github.com/TaceoLabs/circom-mpc-compiler/commit/d312f93875bb13867cb4a03a756807da41e33e95))

### 📚 Documentation


- Fix some docs and add --document-private-items to CI - ([34b41d3](https://github.com/TaceoLabs/circom-mpc-compiler/commit/34b41d31275b40c17c6d10e6593a03f22dae9c88))

### ⚡ Performance


- *(iszero)* Batch the plain-path inversions across a batch - ([0433339](https://github.com/TaceoLabs/circom-mpc-compiler/commit/0433339349d1656ebf0fae297ab4affc0969b3c7))
- *(poseidon2)* Reuse round buffers instead of allocating per round - ([cc35bd2](https://github.com/TaceoLabs/circom-mpc-compiler/commit/cc35bd2bf29f09ad1a229d588920849533ca6b2a))
- *(poseidon2)* Replace small constant multiplications with additions - ([6c7872e](https://github.com/TaceoLabs/circom-mpc-compiler/commit/6c7872e14938322aee313ff236fff24163f00c23))
- *(vm)* Build the public and secret witness parts separately - ([b05a86a](https://github.com/TaceoLabs/circom-mpc-compiler/commit/b05a86ab8d28f2ddc69abb53d5c04e5c7af1e921))
- Use MontFp over string parsing and use rayon to batch plain poseidon calls ([#21](https://github.com/TaceoLabs/circom-mpc-compiler/pull/21)) - ([9694039](https://github.com/TaceoLabs/circom-mpc-compiler/commit/96940392d3a5c5b40843fa453a1b0b136b99cc0c))

