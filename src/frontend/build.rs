//! Per-template lowering: walks one circom template's bucket instructions and builds a
//! [`TemplateGraph`] — the not-yet-inlined value graph for that single template. Reading a
//! variable (`AddressType::Variable`) is a direct `ValueId` lookup, not a node of its own — there
//! is no `Op::Load` in this IR.

use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Zero};
use circom_compiler::circuit_design::template::TemplateCode;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, BranchBucket, ComputeBucket, CreateCmpBucket, Instruction,
    LoadBucket, LocationRule, OperatorType, SizeOption, StoreBucket, ValueBucket, ValueType,
};
use eyre::Result;
use num_bigint::BigUint;
use rustc_hash::FxHashMap;

use crate::ir::{Op, PrecomputeKind, ValueId};

use super::fold::{fold_binary, fold_condition, fold_unary_condition};

const MAPPED_LOCATION: &str =
    "unsupported mapped location rule (bus/anonymous component access)";

pub(crate) fn to_u64(x: usize) -> u64 {
    u64::try_from(x).expect("fits into u64")
}

pub(crate) fn to_usize<F: PrimeField>(c: F) -> usize {
    let big_int: BigUint = c.into_bigint().into();
    usize::try_from(big_int).expect("field element does not fit into usize")
}

/// One operation of a not-yet-inlined per-template graph. Four of these variants are
/// placeholders that only make sense before inlining resolves them:
/// - [`TemplateOp::LocalSignal`] / [`TemplateOp::LocalSignalWrite`]: this template's own input or
///   output signal, addressed by its local (pre-offset) index. Whether a `LocalSignal` read
///   becomes a genuine external input (main) or an alias for whatever the caller fed into that
///   port (a nested subcomponent) is decided during inlining, not here.
/// - [`TemplateOp::SubCmpInput`] / [`TemplateOp::SubCmpOutput`]: a port of a *local* subcomponent
///   instance, addressed by that instance's index within this template.
#[derive(Clone)]
pub(crate) enum TemplateOp<F: PrimeField> {
    LocalSignal(usize),
    LocalSignalWrite(usize),
    SubCmpInput { sub_cmp: usize, port: usize },
    SubCmpOutput { sub_cmp: usize, port: usize },
    Real(Op<F>),
}

impl<F: PrimeField> TemplateOp<F> {
    fn arity(&self) -> usize {
        match self {
            TemplateOp::LocalSignal(_) | TemplateOp::SubCmpOutput { .. } => 0,
            TemplateOp::LocalSignalWrite(_) | TemplateOp::SubCmpInput { .. } => 1,
            // TemplateOp::Real is only ever built from Op::Input/Constant/Add/Sub/Mul here -
            // precomputation and MPC-lowering ops are materialized later, by inlining and
            // passes/mpc respectively, never by this per-template build pass.
            TemplateOp::Real(op) => op
                .fixed_arity()
                .expect("TemplateOp::Real never wraps a precomputation or MPC-lowering op"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct TemplateNode<F: PrimeField> {
    pub(crate) op: TemplateOp<F>,
    pub(crate) inputs: Vec<ValueId>,
}

/// One instantiation of a subcomponent inside a template: which template it is, and at what
/// signal offset in the enclosing circuit's flat signal space it lives.
#[derive(Clone)]
pub(crate) enum SubGraphInstance<F: PrimeField> {
    /// A regular subcomponent, to be recursively inlined by `frontend/inline.rs`.
    Compiled {
        template: TemplateGraph<F>,
        signal_offset: usize,
    },
    /// A recognized gadget template: its body is never compiled - `frontend/inline.rs` turns this
    /// into an `ir::Op::Precompute` site instead of recursing.
    Precomputed(PrecomputedInstance),
}

/// One recognized gadget instance: everything `frontend/inline.rs` needs to cut it into a
/// precomputation site. Resolved once in `handle_create_cmp_bucket` rather than re-derived every
/// time the instance is inlined.
#[derive(Clone)]
pub(crate) struct PrecomputedInstance {
    pub(crate) kind: PrecomputeKind,
    /// The template's specialized header, e.g. `"Poseidon2_3"` (`TemplateCodeInfo::header`) -
    /// the key `precompute_spans` is looked up by.
    pub(crate) header: String,
    /// Relative to the immediate father's signal frame, like every
    /// `CreateCmpBucket::signal_offset`.
    pub(crate) signal_offset: usize,
    pub(crate) num_inputs: usize,
    pub(crate) num_outputs: usize,
    pub(crate) num_intermediates: usize,
}

/// The not-yet-inlined value graph of a single template. `sub_graphs[i]` is the i-th
/// subcomponent instantiated by this template's body, in creation order — matching the
/// `sub_cmp` index used by [`TemplateOp::SubCmpInput`] / [`TemplateOp::SubCmpOutput`].
#[derive(Clone)]
pub(crate) struct TemplateGraph<F: PrimeField> {
    pub(crate) nodes: Vec<TemplateNode<F>>,
    pub(crate) sub_graphs: Vec<SubGraphInstance<F>>,
}

pub(crate) struct GraphCompiler<'a, P: Pairing> {
    pub(crate) nodes: Vec<TemplateNode<P::ScalarField>>,
    pub(crate) var_to_value: FxHashMap<usize, ValueId>,
    pub(crate) sub_graphs: Vec<SubGraphInstance<P::ScalarField>>,
    pub(crate) code: TemplateCode,
    pub(crate) templates: &'a mut HashMap<String, TemplateCode>,
    pub(crate) compiled_graphs: &'a mut FxHashMap<String, TemplateGraph<P::ScalarField>>,
    pub(crate) constant_table: &'a [P::ScalarField],
    /// Every template header's total flat signal count (own signals + everything transitively
    /// instantiated), keyed the same way `templates` is - see
    /// `frontend/mod.rs::compute_signal_spans`. Only consulted for recognized gadget templates, to
    /// size their site's `num_intermediates`.
    pub(crate) precompute_spans: &'a FxHashMap<String, usize>,
}

impl<'a, P: Pairing> GraphCompiler<'a, P> {
    pub(crate) fn new(
        code: TemplateCode,
        templates: &'a mut HashMap<String, TemplateCode>,
        compiled_graphs: &'a mut FxHashMap<String, TemplateGraph<P::ScalarField>>,
        constant_table: &'a [P::ScalarField],
        precompute_spans: &'a FxHashMap<String, usize>,
    ) -> Self {
        Self {
            sub_graphs: Vec::with_capacity(code.number_of_components),
            code,
            nodes: Vec::with_capacity(1024),
            templates,
            compiled_graphs,
            constant_table,
            precompute_spans,
            var_to_value: FxHashMap::default(),
        }
    }

    pub(crate) fn push(&mut self, op: TemplateOp<P::ScalarField>, inputs: Vec<ValueId>) -> ValueId {
        debug_assert_eq!(inputs.len(), op.arity(), "template node arity mismatch");
        let id = ValueId::new(self.nodes.len());
        self.nodes.push(TemplateNode { op, inputs });
        id
    }

    pub(crate) fn push_constant_value(&mut self, constant: P::ScalarField) -> ValueId {
        self.push(TemplateOp::Real(Op::Constant(constant)), vec![])
    }

    fn push_constant(&mut self, index: usize) -> ValueId {
        self.push_constant_value(self.constant_table[index])
    }

    fn push_local_signal_read(&mut self, signal: usize) -> ValueId {
        self.push(TemplateOp::LocalSignal(signal), vec![])
    }

    fn push_local_signal_write(&mut self, signal: usize, value: ValueId) {
        self.push(TemplateOp::LocalSignalWrite(signal), vec![value]);
    }

    fn push_sub_cmp_input(&mut self, sub_cmp: usize, port: usize, value: ValueId) {
        self.push(TemplateOp::SubCmpInput { sub_cmp, port }, vec![value]);
    }

    fn push_sub_cmp_output_read(&mut self, sub_cmp: usize, port: usize) -> ValueId {
        self.push(TemplateOp::SubCmpOutput { sub_cmp, port }, vec![])
    }

    /// Evaluates `inst`, panicking if it is a statement that produces no value. Used for the
    /// small set of syntactic positions (operands of a compute bucket, source of a store) where
    /// circom's bytecode guarantees an expression, not a statement.
    fn expect_value(&mut self, inst: &Instruction) -> Result<ValueId> {
        Ok(self
            .handle_inst(inst)?
            .expect("instruction was expected to produce a value"))
    }

    /// Reads the value at `index` under `address_type` - the read half of what a scalar
    /// [`LoadBucket`] does, factored out so bulk (whole-array) copies in
    /// [`Self::handle_bulk_store_bucket`] can do the same read at a range of indices instead of
    /// just the one `handle_load_bucket` resolves.
    fn read_value_at(&mut self, address_type: &AddressType, index: usize) -> ValueId {
        match address_type {
            AddressType::Variable => *self
                .var_to_value
                .get(&index)
                .expect("variable read before it was stored"),
            AddressType::Signal => self.push_local_signal_read(index),
            AddressType::SubcmpSignal {
                cmp_address,
                is_output,
                ..
            } => {
                debug_assert!(*is_output);
                let cmp_index = self.get_constant_value(cmp_address);
                self.push_sub_cmp_output_read(cmp_index, index)
            }
        }
    }

    /// Writes `value` at `index` under `address_type` - the write half of what a scalar
    /// [`StoreBucket`] does, factored out for the same reason as [`Self::read_value_at`].
    fn write_value_at(&mut self, address_type: &AddressType, index: usize, value: ValueId) {
        match address_type {
            AddressType::Variable => {
                self.var_to_value.insert(index, value);
            }
            AddressType::Signal => self.push_local_signal_write(index, value),
            AddressType::SubcmpSignal {
                cmp_address,
                is_output,
                ..
            } => {
                debug_assert!(!*is_output);
                let cmp_index = self.get_constant_value(cmp_address);
                self.push_sub_cmp_input(cmp_index, index, value);
            }
        }
    }

    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) -> Result<()> {
        match &store_bucket.context.size {
            SizeOption::Single(n) if *n > 1 => {
                return self.handle_bulk_store_bucket(store_bucket, *n)
            }
            SizeOption::Multiple(_) => {
                return Err(self.unsupported(
                    "unsupported instruction `bulk copy spanning multiple component instances`",
                    store_bucket.line,
                ));
            }
            _ => {}
        }

        let value = self.expect_value(&store_bucket.src)?;
        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                let index = self.get_constant_value(location);
                self.write_value_at(&store_bucket.dest_address_type, index, value);
            }
            LocationRule::Mapped { .. } => {
                return Err(self.unsupported(MAPPED_LOCATION, store_bucket.line));
            }
        }
        Ok(())
    }

    /// Handles a whole-array (or array-slice) copy into a destination, represented by circom as
    /// one [`StoreBucket`] whose `context.size` spans multiple contiguous signals rather than one
    /// scalar store per element. Reads and writes all `size` contiguous elements, addressed as
    /// `base + i` on both sides (circom lays an array's elements out contiguously, so the base
    /// resolved once plus a stride of 1 per element is exactly what a real per-element store/load
    /// pair would compute).
    fn handle_bulk_store_bucket(&mut self, store_bucket: &StoreBucket, size: usize) -> Result<()> {
        let Instruction::Load(src_load) = store_bucket.src.as_ref() else {
            return Err(self.err_bulk_copy_shape(store_bucket));
        };
        let LocationRule::Indexed {
            location: src_location,
            template_header: _,
        } = &src_load.src
        else {
            return Err(self.err_bulk_copy_shape(store_bucket));
        };
        let src_base = self.get_constant_value(src_location);
        let src_address_type = src_load.address_type.clone();

        let LocationRule::Indexed {
            location: dest_location,
            template_header: _,
        } = &store_bucket.dest
        else {
            return Err(self.unsupported(MAPPED_LOCATION, store_bucket.line));
        };
        let dest_base = self.get_constant_value(dest_location);
        let dest_address_type = store_bucket.dest_address_type.clone();

        for i in 0..size {
            let value = self.read_value_at(&src_address_type, src_base + i);
            self.write_value_at(&dest_address_type, dest_base + i, value);
        }
        Ok(())
    }

    fn err_bulk_copy_shape(&self, store_bucket: &StoreBucket) -> eyre::Report {
        self.unsupported(
            format!(
                "unsupported instruction `bulk copy whose source is not a plain indexed load: {}`",
                store_bucket.src.to_string()
            ),
            store_bucket.line,
        )
    }

    /// Pushes one [`SubGraphInstance`] per repetition of `create_cmp_bucket`, at consecutive
    /// signal offsets - the shape every `SubGraphInstance` arm is instantiated with.
    fn push_instances(
        &mut self,
        create_cmp_bucket: &CreateCmpBucket,
        mut make: impl FnMut(usize) -> SubGraphInstance<P::ScalarField>,
    ) {
        let mut offset = create_cmp_bucket.signal_offset;
        let offset_jump = create_cmp_bucket.signal_offset_jump;
        for _ in 0..create_cmp_bucket.number_of_cmp {
            self.sub_graphs.push(make(offset));
            offset += offset_jump;
        }
    }

    fn handle_create_cmp_bucket(&mut self, create_cmp_bucket: &CreateCmpBucket) -> Result<()> {
        tracing::debug!(
            "we need to create {} {} times",
            create_cmp_bucket.symbol,
            create_cmp_bucket.number_of_cmp
        );
        let symbol = create_cmp_bucket.symbol.clone();

        // Fast path: already compiled. A precomputed gadget's entry is never inserted into
        // `compiled_graphs` (see below), so every repeated instantiation of one keeps going
        // through the peek further down instead. Handling this first, before touching
        // `self.templates` at all, matters: a regular template's entry there is removed the first
        // time it's compiled (below), so a naive peek-first order would panic on a *second*
        // instantiation of any repeated regular template.
        if let Some(sub_cmp) = self.compiled_graphs.get(&symbol) {
            let sub_cmp = sub_cmp.clone();
            self.push_instances(create_cmp_bucket, |signal_offset| {
                SubGraphInstance::Compiled {
                    template: sub_cmp.clone(),
                    signal_offset,
                }
            });
            return Ok(());
        }

        // A gadget this compiler services out-of-band is always cut into a precomputation site:
        // its body is never compiled, and `vm::gadgets` supplies its trace instead. Resolved from
        // the *instantiated* template's name, so this fires the same way whether or not the
        // enclosing template wraps it.
        //
        // Peek, never remove: the wrapped component's body is never compiled at all (see
        // `SubGraphInstance::Precomputed`), so its entry in `templates` must stay put for every
        // repeated instantiation to find it too.
        let template_code = self.templates.get(&symbol).expect("must be here");
        let header = template_code.header.clone();
        let num_inputs = template_code.number_of_inputs;
        let num_outputs = template_code.number_of_outputs;

        let kind = match template_code.name.as_str() {
            "Poseidon2" => Some(PrecomputeKind::Poseidon2 { t: num_inputs }),
            "Num2Bits" => Some(PrecomputeKind::Num2Bits { n: num_outputs }),
            "IsZero" => Some(PrecomputeKind::IsZero),
            "AliasCheck" => Some(PrecomputeKind::AliasCheck),
            "TACEO_REVEAL" => Some(PrecomputeKind::Reveal { n: num_inputs }),
            _ => None,
        };

        if let Some(kind) = kind {
            let span = *self.precompute_spans.get(&header).unwrap_or_else(|| {
                panic!("no signal-span entry for precomputed template `{header}`")
            });
            let num_intermediates = span - num_inputs - num_outputs;

            self.push_instances(create_cmp_bucket, |signal_offset| {
                SubGraphInstance::Precomputed(PrecomputedInstance {
                    kind,
                    header: header.clone(),
                    signal_offset,
                    num_inputs,
                    num_outputs,
                    num_intermediates,
                })
            });
            return Ok(());
        }

        // First instantiation of a regular (non-precomputed) template: compile it now and cache
        // the result for every later instantiation to hit the fast path above.
        let template_code = self.templates.remove(&symbol).expect("must be here");
        tracing::debug!("start compilation of {}", symbol);
        let sub_cmp_compiler = GraphCompiler::<P>::new(
            template_code,
            self.templates,
            self.compiled_graphs,
            self.constant_table,
            self.precompute_spans,
        );
        let sub_cmp = sub_cmp_compiler.parse()?;
        self.compiled_graphs.insert(symbol.clone(), sub_cmp.clone());

        self.push_instances(create_cmp_bucket, |signal_offset| {
            SubGraphInstance::Compiled {
                template: sub_cmp.clone(),
                signal_offset,
            }
        });
        Ok(())
    }

    /// Unwraps `inst` until it finds a value known at compile time (used for array/signal/loop
    /// addresses) - panics if that is not possible.
    /// Recursively evaluates a template-local node at compile time, for use as an array/signal/
    /// component address. `Op::Constant` is the base case; `Add`/`Sub`/`Mul` fold if both operands
    /// do (this is a narrow, address-position-only fold - it does not touch the graph, unlike a
    /// general CSE/constant-folding pass, which stays out of scope here). Returns `None` if the
    /// node bottoms out in a genuine circuit value (`Input`, an unresolved `LocalSignal`, a
    /// `SubCmpOutput`, ...), which is a real "not a compile-time constant" case, not a bug.
    ///
    /// This exists because circom sometimes tracks more than one loop counter in lockstep - e.g. a
    /// template's own `for (var i = ...)` induction variable, canonicalized to a fresh
    /// `Op::Constant` every iteration by `unroll.rs::add_induction_variable_node`, *and* a second,
    /// circom-internal shadow counter (observed for a loop that instantiates an anonymous
    /// component per iteration) that is only ever incremented via a genuine `var = var + 1` store,
    /// never canonicalized. That shadow counter is still a compile-time constant at every
    /// iteration - unroll.rs just never rewrites it to a literal `Op::Constant` node the way it
    /// does for the one variable it tracks explicitly - so without this fold it looked
    /// indistinguishable from a real non-constant value.
    fn eval_constant_node(&self, value_id: ValueId) -> Option<P::ScalarField> {
        let node = &self.nodes[value_id.index()];
        match &node.op {
            TemplateOp::Real(Op::Constant(c)) => Some(*c),
            TemplateOp::Real(Op::Add) => Some(
                self.eval_constant_node(node.inputs[0])? + self.eval_constant_node(node.inputs[1])?,
            ),
            TemplateOp::Real(Op::Sub) => Some(
                self.eval_constant_node(node.inputs[0])? - self.eval_constant_node(node.inputs[1])?,
            ),
            TemplateOp::Real(Op::Mul) => Some(
                self.eval_constant_node(node.inputs[0])? * self.eval_constant_node(node.inputs[1])?,
            ),
            TemplateOp::Real(Op::Input(_))
            // Precompute/PrecomputeResult/MulLocal/Round/RoundResult are inlining-or-lowering-time-
            // only ops (see TemplateOp::arity above) and never appear here, but are included so
            // this match stays exhaustive as Op grows.
            | TemplateOp::Real(Op::Precompute(_))
            | TemplateOp::Real(Op::PrecomputeResult(_))
            | TemplateOp::Real(Op::MulLocal)
            | TemplateOp::Real(Op::Round(_))
            | TemplateOp::Real(Op::RoundResult(_))
            | TemplateOp::LocalSignal(_)
            | TemplateOp::LocalSignalWrite(_)
            | TemplateOp::SubCmpInput { .. }
            | TemplateOp::SubCmpOutput { .. } => None,
        }
    }

    pub(crate) fn get_constant_value(&self, inst: &Instruction) -> usize {
        match inst {
            Instruction::Value(value_bucket) => match value_bucket.parse_as {
                ValueType::U32 => value_bucket.value,
                ValueType::BigInt => to_usize(self.constant_table[value_bucket.value]),
            },
            Instruction::Load(load_bucket) => {
                let index = if let LocationRule::Indexed {
                    location,
                    template_header: _,
                } = &load_bucket.src
                {
                    self.get_constant_value(location)
                } else {
                    todo!("get_constant_load not indexed")
                };
                if let AddressType::Variable = &load_bucket.address_type {
                    let value_id = *self.var_to_value.get(&index).expect("must be there");
                    to_usize(
                        self.eval_constant_node(value_id).unwrap_or_else(|| {
                            panic!("non constant loading in get constant value")
                        }),
                    )
                } else {
                    panic!("non variable loading in get constant value");
                }
            }
            Instruction::Compute(compute_bucket) => match compute_bucket.op {
                OperatorType::MulAddress => {
                    assert_eq!(compute_bucket.stack.len(), 2, "mul is a bin op");
                    self.get_constant_value(&compute_bucket.stack[0])
                        * self.get_constant_value(&compute_bucket.stack[1])
                }
                OperatorType::AddAddress => {
                    assert_eq!(compute_bucket.stack.len(), 2, "add is a bin op");
                    self.get_constant_value(&compute_bucket.stack[0])
                        + self.get_constant_value(&compute_bucket.stack[1])
                }
                OperatorType::ToAddress => {
                    assert_eq!(compute_bucket.stack.len(), 1, "to address is a unary op");
                    self.get_constant_value(&compute_bucket.stack[0])
                }
                // circom does not always route address arithmetic through the dedicated
                // `*Address` operators above - idioms like reverse indexing (`arr[N-1-i]`, seen in
                // merces' AliasCheck-style bit-reversal loops) or modular indexing (`arr[i % n]`,
                // seen in poseidon/sha256-style round tables) compile to a plain `Sub`/`Add`/`Mod`
                // compute bucket in address position, same as they would for a genuine signal
                // value. Treat these the same way as the `*Address` variants: recurse and combine.
                OperatorType::Sub => {
                    assert_eq!(compute_bucket.stack.len(), 2, "sub is a bin op");
                    self.get_constant_value(&compute_bucket.stack[0])
                        - self.get_constant_value(&compute_bucket.stack[1])
                }
                OperatorType::Add => {
                    assert_eq!(compute_bucket.stack.len(), 2, "add is a bin op");
                    self.get_constant_value(&compute_bucket.stack[0])
                        + self.get_constant_value(&compute_bucket.stack[1])
                }
                OperatorType::Mod => {
                    assert_eq!(compute_bucket.stack.len(), 2, "mod is a bin op");
                    self.get_constant_value(&compute_bucket.stack[0])
                        % self.get_constant_value(&compute_bucket.stack[1])
                }
                x => panic!(
                    "compute for constant must be add/mul address but is {}",
                    x.to_string()
                ),
            },
            x => panic!("cannot get constant of {}", x.to_string()),
        }
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket) -> Result<ValueId> {
        tracing::trace!(
            "lowering {} at line: {}",
            compute_bucket.op.to_string(),
            compute_bucket.line
        );

        // Add/Sub/Mul are the only runtime ir::Op variants; everything else is either a
        // compile-time-only address computation (ToAddress/MulAddress/AddAddress, handled
        // separately by get_constant_value - if one reaches here it has leaked into value
        // position) or a removed operator that only survives if every operand folds to a
        // constant (Div/IntDiv/Pow/Shift*/Bit*), or genuinely unsupported (comparisons, Mod,
        // booleans, ...).
        match compute_bucket.op {
            OperatorType::Add | OperatorType::Sub | OperatorType::Mul => {
                let operands = compute_bucket
                    .stack
                    .iter()
                    .map(|inst| self.expect_value(inst))
                    .collect::<Result<Vec<_>>>()?;
                let op = match compute_bucket.op {
                    OperatorType::Add => Op::Add,
                    OperatorType::Sub => Op::Sub,
                    OperatorType::Mul => Op::Mul,
                    _ => unreachable!(),
                };
                Ok(self.push(TemplateOp::Real(op), operands))
            }
            OperatorType::ToAddress | OperatorType::MulAddress | OperatorType::AddAddress => {
                Err(self.err_address_operator(compute_bucket))
            }
            removed @ (OperatorType::Div
            | OperatorType::IntDiv
            | OperatorType::Pow
            | OperatorType::ShiftL
            | OperatorType::ShiftR
            | OperatorType::BitOr
            | OperatorType::BitAnd
            | OperatorType::BitXor) => {
                assert_eq!(
                    compute_bucket.stack.len(),
                    2,
                    "{} is a bin op",
                    removed.to_string()
                );
                let lhs = self.eval_constant_operand(&compute_bucket.stack[0]);
                let rhs = self.eval_constant_operand(&compute_bucket.stack[1]);
                match lhs.zip(rhs).and_then(|(l, r)| fold_binary(removed, l, r)) {
                    Some(folded) => Ok(self.push_constant_value(folded)),
                    None => Err(self.err_non_constant_operator(compute_bucket)),
                }
            }
            _ => Err(self.err_operator(compute_bucket)),
        }
    }

    /// A circom construct this compiler deliberately does not support (yet, or ever).
    /// `tests/frontend.rs` and `tests/merces.rs` pin several of these message prefixes.
    fn unsupported(&self, msg: impl std::fmt::Display, line: usize) -> eyre::Report {
        eyre::eyre!("{msg} in template `{}` at line {line}", self.code.header)
    }

    fn err_operator(&self, compute_bucket: &ComputeBucket) -> eyre::Report {
        self.unsupported(
            format!("unsupported operator `{}`", compute_bucket.op.to_string()),
            compute_bucket.line,
        )
    }

    fn err_non_constant_operator(&self, compute_bucket: &ComputeBucket) -> eyre::Report {
        self.unsupported(
            format!(
                "operator `{}` is only supported on compile-time constants",
                compute_bucket.op.to_string()
            ),
            compute_bucket.line,
        )
    }

    fn err_address_operator(&self, compute_bucket: &ComputeBucket) -> eyre::Report {
        self.unsupported(
            format!(
                "address operator `{}` in value position (dynamic array indexing)",
                compute_bucket.op.to_string()
            ),
            compute_bucket.line,
        )
    }

    fn handle_value_bucket(&mut self, value_bucket: &ValueBucket) -> Result<ValueId> {
        match value_bucket.parse_as {
            ValueType::BigInt => Ok(self.push_constant(value_bucket.value)),
            ValueType::U32 => unreachable!("this should never happen!!!! (I guess )"),
        }
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) -> Result<ValueId> {
        // for load we have three cases:
        //   1.) load a variable         -> direct ValueId lookup, no node
        //   2.) load a (local) signal   -> resolved during inlining
        //   3.) load from a subcmp      -> resolved during inlining
        //
        // This always resolves exactly one value, at one index - a load bucket with
        // `context.size > 1` (a bulk array read) only ever reaches here as the `src` of a
        // `StoreBucket`, which `handle_bulk_store_bucket` handles directly without going through
        // this function (it needs `size` separate reads, not one).
        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                let index = self.get_constant_value(location);
                Ok(self.read_value_at(&load_bucket.address_type, index))
            }
            LocationRule::Mapped { .. } => {
                Err(self.unsupported(MAPPED_LOCATION, load_bucket.line))
            }
        }
    }

    fn err_instruction(&self, kind: &str, line: usize) -> eyre::Report {
        self.unsupported(format!("unsupported instruction `{kind}`"), line)
    }

    /// `if`/`else` on a **compile-time-constant** condition: evaluate the condition, then lower only
    /// the taken arm's instructions inline. The untaken arm is never visited, so anything unsupported
    /// inside it is irrelevant - which is the point, since circom emits a real `Branch` for
    /// `if (i == 0)` inside an unrolled loop, where `i` is a fresh `Op::Constant` every iteration
    /// (`unroll.rs::add_induction_variable_node`).
    ///
    /// A *non*-constant condition stays an `Unsupported` error, and structurally has to: `ir::Op` is
    /// only `Add`/`Sub`/`Mul`, so there is no select/mux op to arithmetize a secret-dependent branch
    /// into. Supporting it means re-adding the operator surface, not extending this function.
    fn handle_branch_bucket(&mut self, branch_bucket: &BranchBucket) -> Result<()> {
        let Some(taken) = self.fold_branch_condition(branch_bucket.cond.as_ref()) else {
            return Err(self.err_instruction(
                "branch (if/else on a non-constant condition)",
                branch_bucket.line,
            ));
        };
        let body = if taken {
            &branch_bucket.if_branch
        } else {
            &branch_bucket.else_branch
        };
        for inst in body {
            self.handle_inst(inst)?;
        }
        Ok(())
    }

    /// `Some(bool)` iff this condition is decidable at compile time. Three shapes occur in practice:
    /// a comparison/boolean binary op, a `!` on a constant, and a bare value used for its truthiness.
    fn fold_branch_condition(&mut self, cond: &Instruction) -> Option<bool> {
        if let Instruction::Compute(compute_bucket) = cond {
            match compute_bucket.stack.len() {
                2 => {
                    let lhs = self.eval_constant_operand(&compute_bucket.stack[0])?;
                    let rhs = self.eval_constant_operand(&compute_bucket.stack[1])?;
                    if let Some(folded) = fold_condition(compute_bucket.op, lhs, rhs) {
                        return Some(folded);
                    }
                    // Not a comparison - an *arithmetic* expression used for its truthiness
                    // (`if (a - b)`). Fold the arithmetic, then test against zero.
                    let value = fold_binary(compute_bucket.op, lhs, rhs)?;
                    return Some(!value.is_zero());
                }
                1 => {
                    let operand = self.eval_constant_operand(&compute_bucket.stack[0])?;
                    return fold_unary_condition(compute_bucket.op, operand);
                }
                _ => return None,
            }
        }
        // A plain value or variable read: truthy iff non-zero, matching circom's own `if (x)`.
        self.eval_constant_operand(cond).map(|v| !v.is_zero())
    }

    /// Like [`Self::get_constant_operand`], but folds `Add`/`Sub`/`Mul` chains of constants rather
    /// than requiring the operand to *already* be a single `Op::Constant` node.
    ///
    /// Needed because this build pass deliberately doesn't fold arithmetic (that's `passes::
    /// const_fold`'s job, which runs much later), so a `var` computed from constants is a real
    /// `Op::Sub`/`Add`/`Mul` node here even though its value is fixed. Real circom does this
    /// constantly: `circuits/libs/taceo/compression.circom`'s `Poseidon2SpongeWithDs` guards
    /// `if (remaining > T - 1)` where `remaining = N - absorbed`, all compile-time.
    ///
    /// Shares [`Self::eval_constant_node`] with address computation, which needs the identical
    /// capability for `arr[N-1-i]`-style indexing.
    fn eval_constant_operand(&mut self, inst: &Instruction) -> Option<P::ScalarField> {
        let value_id = self.expect_value(inst).ok()?;
        self.eval_constant_node(value_id)
    }

    pub(crate) fn handle_inst(&mut self, inst: &Instruction) -> Result<Option<ValueId>> {
        match inst {
            Instruction::Value(value_bucket) => Ok(Some(self.handle_value_bucket(value_bucket)?)),
            Instruction::Load(load_bucket) => Ok(Some(self.handle_load_bucket(load_bucket)?)),
            Instruction::Store(store_bucket) => {
                self.handle_store_bucket(store_bucket)?;
                Ok(None)
            }
            Instruction::Compute(compute_bucket) => {
                Ok(Some(self.handle_compute_bucket(compute_bucket)?))
            }
            Instruction::Call(call_bucket) => Err(self.err_instruction(
                &format!("call to function `{}`", call_bucket.symbol),
                call_bucket.line,
            )),
            Instruction::Branch(branch_bucket) => {
                self.handle_branch_bucket(branch_bucket)?;
                Ok(None)
            }
            Instruction::Return(return_bucket) => {
                Err(self.err_instruction("return", return_bucket.line))
            }
            // `===` constraints do not affect witness extension.
            Instruction::Assert(_) => Ok(None),
            Instruction::Log(log_bucket) => Err(self.err_instruction("log", log_bucket.line)),
            Instruction::Loop(loop_bucket) => {
                self.handle_loop_bucket(loop_bucket)?;
                Ok(None)
            }
            Instruction::CreateCmp(create_cmp_bucket) => {
                self.handle_create_cmp_bucket(create_cmp_bucket)?;
                Ok(None)
            }
        }
    }

    pub(crate) fn parse(mut self) -> Result<TemplateGraph<P::ScalarField>> {
        tracing::debug!("parsing {}", self.code.header);
        let body = std::mem::take(&mut self.code.body);
        for inst in body.iter() {
            self.handle_inst(inst)?;
        }
        Ok(TemplateGraph {
            nodes: self.nodes,
            sub_graphs: self.sub_graphs,
        })
    }
}

// loop unrolling lives in `super::unroll` as an `impl` block on `GraphCompiler`.
