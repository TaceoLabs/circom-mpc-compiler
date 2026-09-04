//! Witness-extension benchmark case registry, shared by `benches/{compile,witness_extension}.rs`
//! and `src/bin/witext-bench.rs`. Adding a benchmark is adding one entry to [`all`] - nothing else
//! needs to change. A registered circuit is allowed to not compile with today's compiler; callers
//! should skip such a case (with a printed warning) rather than treat [`compile`]'s error as
//! fatal.

use std::{collections::BTreeSet, path::PathBuf};

use circom_mpc_compiler::{CompilerConfig, OptLevel};
use circom_mpc_program::{Bank, Program};

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

fn circuits_dir() -> PathBuf {
    PathBuf::from(manifest_dir()).join("circuits")
}

/// One benchmark case: a circuit and how to compile it.
#[derive(Clone)]
pub struct Case {
    /// Benchmark label, `<group>/<name>` (e.g. `merces/batch32`).
    pub name: String,
    /// The circuit's `.circom` file.
    pub path: PathBuf,
    /// How to compile it.
    pub config: CompilerConfig,
    /// Exact signal names expected to be public in the compiled MPC program. This includes both
    /// Circom-native public inputs and `CompilerConfig::mpc_public_inputs`.
    pub expected_public_inputs: Vec<String>,
}

fn base_config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(circuits_dir().join("node_modules"));
    config
}

/// A `circuits/<name>.circom` case, labelled `micro/<name>`. These circuits exist to measure
/// secret-multiplication rounds (chains, trees, batched products), so they are deliberately kept
/// all-secret: any public input would turn a `MulSS` into the round-free `MulSP`/`MulPP` and
/// delete the very rounds they were built to count.
fn micro(name: &str) -> Case {
    Case {
        name: format!("micro/{name}"),
        path: circuits_dir().join(format!("{name}.circom")),
        config: base_config(),
        expected_public_inputs: Vec::new(),
    }
}

/// A `circuits/bench/<name>.circom` case (a thin `component main` over circomlib), labelled
/// `lib/<name>`. `mpc_public` names the inputs a real deployment would hold in cleartext (e.g. a
/// published Merkle root, an issuer's public key, a mode selector) - see `cases::all` for the
/// per-circuit rationale.
fn lib(name: &str, mpc_public: &[&str]) -> Case {
    let mut config = base_config();
    config.mpc_public_inputs = mpc_public.iter().copied().map(String::from).collect();
    Case {
        name: format!("lib/{name}"),
        path: circuits_dir().join("bench").join(format!("{name}.circom")),
        expected_public_inputs: config.mpc_public_inputs.clone(),
        config,
    }
}

/// `circuits/merces/main/transfer_arity4_batch<n>.circom`, labelled `merces/batch<n>` - the
/// vendored `TransferBatchedCompressedArity4` circuit at transaction-batch size `n`.
fn merces_batch(n: usize) -> Case {
    let mut config = base_config();
    config.link_library.push(circuits_dir().join("merces"));
    config.opt_level = OptLevel::O2;
    config.mpc_public_inputs = crate::fixtures::merces_mpc_public_inputs();
    let mut expected_public_inputs = config.mpc_public_inputs.clone();
    // `alpha` is declared public by the Circom `component main`; the other entries are public only
    // to the MPC execution and remain private Groth16 witness values.
    expected_public_inputs.push("alpha".to_owned());
    Case {
        name: format!("merces/batch{n}"),
        path: circuits_dir()
            .join("merces")
            .join("main")
            .join(format!("transfer_arity4_batch{n}.circom")),
        expected_public_inputs,
        config,
    }
}

/// Merces batches for the given transaction counts. Each `n` needs a matching
/// `circuits/merces/main/transfer_arity4_batch<n>.circom`.
pub fn merces(batches: impl IntoIterator<Item = usize>) -> Vec<Case> {
    batches.into_iter().map(merces_batch).collect()
}

/// Every registered case, across every group. Add a benchmark here.
pub fn all() -> Vec<Case> {
    let mut cases = vec![
        micro("bench_chain"),
        micro("bench_tree"),
        micro("bench_widesum"),
        micro("multiplier16"),
        // Hashing/committing to a secret preimage - the whole input is the secret.
        lib("sha256_512", &[]),
        lib("poseidon16", &[]),
        lib("pedersen", &[]),
        // `k` is MiMCFeistel's sponge key, a protocol constant every party knows; `xL_in`/`xR_in`
        // is the secret absorbed state.
        lib("mimc_sponge", &["k"]),
        // Membership proof of a secret key against a published tree root; `enabled`/`fnc` are
        // mode selectors agreed out of band. `siblings`, `key`, `value`, `oldKey`, `oldValue`,
        // `isOld0` are the private witness.
        lib("smt_verifier10", &["enabled", "root", "fnc"]),
        // Verifying a credential against a known issuer public key; `enabled` is a mode selector.
        // The signature and message are the private credential.
        lib("eddsa_poseidon", &["enabled", "Ax", "Ay"]),
        // Range/bit decomposition of secret values.
        lib("num2bits_bench", &[]),
    ];
    cases.extend(merces([8, 32, 50, 100]));
    cases
}

/// Cases whose `name` contains `filter` (a plain substring match); `None` selects every case.
pub fn select(filter: Option<&str>) -> Vec<Case> {
    all()
        .into_iter()
        .filter(|case| filter.is_none_or(|f| case.name.contains(f)))
        .collect()
}

/// Compiles one case and checks its exact public/shared input policy. Matching
/// `config.mpc_public_inputs` is exact-string with no validation in the compiler itself, so a typo
/// would otherwise silently stay `Bank::Shared`; checking the full public set also catches an input
/// being declassified accidentally.
///
/// # Errors
///
/// Returns an error if the circuit fails to compile - not every registered circuit is supported by
/// today's compiler; see the module docs - or if an input's compiled domain differs from the
/// case's declared policy.
pub fn compile(case: &Case) -> eyre::Result<Program> {
    let program = circom_mpc_compiler::compile(case.path.clone(), &case.config)?;
    let mut actual_public = BTreeSet::new();
    for signal in program.input_signals() {
        let domains = &program.input_domains()[signal.offset..signal.offset + signal.size];
        eyre::ensure!(
            domains.iter().all(|domain| *domain == domains[0]),
            "{}: input `{}` has mixed public/shared element domains",
            case.name,
            signal.name,
        );
        if domains[0] == Bank::Public {
            actual_public.insert(signal.name.clone());
        }
    }
    let expected_public: BTreeSet<_> = case.expected_public_inputs.iter().cloned().collect();
    eyre::ensure!(
        actual_public == expected_public,
        "{}: public input mismatch: expected {:?}, compiled {:?}",
        case.name,
        expected_public,
        actual_public,
    );
    Ok(program)
}
