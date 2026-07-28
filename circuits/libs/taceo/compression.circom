pragma circom 2.2.2;

include "precomputations.circom";

// Public input compression via "hybrid compression" (https://eprint.iacr.org/2025/1500,
// "Data Matching in Unequal Worlds and Applications to Smart Contracts").
//
// Instead of exposing a long statement `q` as public inputs to the verifier, `q` is moved
// into the witness and only three field elements remain public: `alpha`, `beta`, `gamma`.
// The statement is hashed with two different hash functions, each on the side where it is
// cheap: the smart contract computes `alpha` (e.g. Keccak256 of `q`, truncated to the
// scalar field - cheap in gas), while this circuit computes `beta` (a Poseidon2 sponge
// over `q` - cheap in constraints). Both sides then evaluate the universal hash
// `gamma = UHF(alpha + beta, q)`, and the verifier checks the proof against
// (alpha, beta, gamma). Soundness reduces to the "joint UHF hardness" of the two hash
// functions (Definition 4 of the paper): finding q != q' with matching UHF outputs under
// the seed `alpha + beta` is infeasible, so matching `gamma` values bind the on-chain
// statement to the in-circuit one.

/// In-circuit side of hybrid compression: derives `beta` and `gamma` for a
/// statement `q`, so the verifier only needs (alpha, beta, gamma) as public inputs.
/// `alpha` must be the on-chain hash of `q` (e.g. Keccak256 truncated to the scalar
/// field) and is expected to be a public input of the enclosing circuit. `beta` is the
/// Poseidon2 sponge hash of `q` and `gamma = UHF(alpha + beta, q)`; the contract
/// recomputes `gamma` from `q`, its own `alpha`, and the prover-supplied `beta`. See
/// https://eprint.iacr.org/2025/1500, Construction 2.
/// * N length of the statement `q`
/// * T Poseidon2 state size used by the sponge (2, 3, 4, 8, 12, or 16)
template Compression(N, T) {
    signal input q[N];
    signal input alpha;
    signal output beta;
    signal output gamma;

    // This is the ASCII byte sequence "eprint.iacr.org/2025/1500+Pos2" interpreted as a field element.
    // It consists of the link to the TwoHash paper, without the leading "https://", concatenated with
    // an identifier for the Poseidon2 hash function.
    var DS = 0x657072696E742E696163722E6F72672F323032352F313530302B506F7332;

    beta <== Poseidon2Sponge(N, T, DS)(q);
    gamma <== UHF(N)(alpha, beta, q);
}

/// Universal hash function UHF(seed, x) = sum_i seed^i * x[i], evaluated via
/// Horner's method with `seed = alpha + beta` (Definition 3 of
/// https://eprint.iacr.org/2025/1500). For a seed the adversary cannot predict before
/// fixing the inputs, two distinct inputs collide with probability O(N / |F|).
template UHF(N) {
    signal input alpha;
    signal input beta;
    signal input x[N];
    signal output gamma;

    assert(N >= 1);

    signal seed <== alpha + beta;
    signal muls[N];
    muls[N - 1] <== 0;
    for (var i = N - 1; i > 0; i--) {
        muls[i - 1] <== seed * (muls[i] + x[i]);
    }
    gamma <== muls[0] + x[0];
}

/// Poseidon2 in sponge mode: rate T-1, one capacity element initialized with the
/// domain separator `DS`, zero-initialized state. Absorbs `in` in chunks of T-1 (the last
/// chunk may be partial, without padding), permuting after each chunk; the output is the
/// first state element. Note: like the paper's nested hashing, this is only safe when the
/// input length N is fixed by the protocol.
/// DS compile-time domain separator, placed in the capacity element
template Poseidon2Sponge(N, T, DS) {
    signal input in[N];
    signal output out;

    out <== Poseidon2SpongeWithDs(N, T)(in, DS);
}


/// Same as `Poseidon2Sponge`, but the domain separator is a runtime signal.
template Poseidon2SpongeWithDs(N, T) {
    signal input in[N];
    signal input ds;
    signal output out;

    assert(T >= 2);
    assert(N >= 1);

    var permutations = (N + T - 2) \ (T-1);
    var states[permutations + 1][T];

    for (var i = 0; i < T - 1; i++) {
        states[0][i] = 0;
    }
    states[0][T - 1] = ds;

    var absorbed = 0;
    for (var p = 0; p < permutations; p++) {
        var remaining = N - absorbed;
        if (remaining > T - 1) {
            remaining = T - 1;
        }
        for (var i = 0; i < remaining; i++) {
            states[p][i] = states[p][i] + in[absorbed + i];
        }
        absorbed += remaining;
        states[p + 1] = TACEO_PRECOMPUTATION_Poseidon2(T)(states[p]);
    }
    out <== states[permutations][0];
}

