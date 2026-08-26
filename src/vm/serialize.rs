//! `Program::write`/`Program::read`: a stable, hand-rolled binary format, independent of any
//! particular Rust type's derive support (`Opcode`/`Bank` are plain fieldless enums over small
//! integers, not `ark_serialize` types). An 8-byte magic + `u32` version identify the format;
//! `constants` (the only field-element table) go through `ark_serialize`'s
//! `CanonicalSerialize`/`CanonicalDeserialize`; everything else uses compact tags and
//! little-endian integers. The instruction stream has a fixed record shape (16 bytes:
//! `u8` opcode + 3 bytes padding + three `u32`s).

use std::io::{Read, Write};

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

struct LittleEndian;

trait WriteLeExt: Write {
    fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&[value])
    }

    fn write_u32<E>(&mut self, value: u32) -> std::io::Result<()> {
        let _ = std::marker::PhantomData::<E>;
        self.write_all(&value.to_le_bytes())
    }

    fn write_u64<E>(&mut self, value: u64) -> std::io::Result<()> {
        let _ = std::marker::PhantomData::<E>;
        self.write_all(&value.to_le_bytes())
    }
}

impl<W: Write + ?Sized> WriteLeExt for W {}

trait ReadLeExt: Read {
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut bytes = [0; 1];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }

    fn read_u32<E>(&mut self) -> std::io::Result<u32> {
        let _ = std::marker::PhantomData::<E>;
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64<E>(&mut self) -> std::io::Result<u64> {
        let _ = std::marker::PhantomData::<E>;
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl<R: Read + ?Sized> ReadLeExt for R {}

use crate::ir::PrecomputeKind;

use super::program::{
    Bank, BatchKind, InputBinding, Instruction, Opcode, PrecomputeBatch, Program, ResultTarget,
    RoundEntry, SiteInput, SlotCounts, WitnessSource,
};

const MAGIC: &[u8; 8] = b"CMPCVM\0\0";
/// Bumped on every layout change; `read` rejects anything else. Deliberately no compatibility
/// shim: accepting an older layout could produce a plausible-looking wrong witness.
const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct ProgramReadLimits {
    pub max_serialized_bytes: u64,
    pub max_estimated_allocation: usize,
    pub max_table_entries: usize,
}

impl Default for ProgramReadLimits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 256 * 1024 * 1024,
            max_estimated_allocation: 256 * 1024 * 1024,
            max_table_entries: 16_777_216,
        }
    }
}

fn checked_count<T>(count: u64, limits: ProgramReadLimits, table: &str) -> eyre::Result<usize> {
    let count =
        usize::try_from(count).map_err(|_| eyre::eyre!("{table} count does not fit usize"))?;
    eyre::ensure!(
        count <= limits.max_table_entries,
        "{table} count {count} exceeds limit {}",
        limits.max_table_entries
    );
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(|| eyre::eyre!("{table} allocation overflows"))?;
    eyre::ensure!(
        bytes <= limits.max_estimated_allocation,
        "{table} allocation exceeds limit"
    );
    Ok(count)
}

impl Opcode {
    fn to_u8(self) -> u8 {
        match self {
            Opcode::AddPP => 0,
            Opcode::SubPP => 1,
            Opcode::MulPP => 2,
            Opcode::AddSS => 3,
            Opcode::SubSS => 4,
            Opcode::AddSP => 5,
            Opcode::SubSP => 6,
            Opcode::SubPS => 7,
            Opcode::MulSP => 8,
            Opcode::MulLocal => 9,
            Opcode::Reshare => 10,
            Opcode::Precompute => 11,
        }
    }

    fn from_u8(b: u8) -> eyre::Result<Self> {
        Ok(match b {
            0 => Opcode::AddPP,
            1 => Opcode::SubPP,
            2 => Opcode::MulPP,
            3 => Opcode::AddSS,
            4 => Opcode::SubSS,
            5 => Opcode::AddSP,
            6 => Opcode::SubSP,
            7 => Opcode::SubPS,
            8 => Opcode::MulSP,
            9 => Opcode::MulLocal,
            10 => Opcode::Reshare,
            11 => Opcode::Precompute,
            other => eyre::bail!("unknown opcode byte {other}"),
        })
    }
}

impl Bank {
    fn to_u8(self) -> u8 {
        match self {
            Bank::Public => 0,
            Bank::Shared => 1,
            Bank::Local => 2,
        }
    }

    fn from_u8(b: u8) -> eyre::Result<Self> {
        Ok(match b {
            0 => Bank::Public,
            1 => Bank::Shared,
            2 => Bank::Local,
            other => eyre::bail!("unknown bank byte {other}"),
        })
    }
}

fn write_u32_vec<W: Write>(w: &mut W, values: &[u32]) -> eyre::Result<()> {
    w.write_u64::<LittleEndian>(values.len() as u64)?;
    for &v in values {
        w.write_u32::<LittleEndian>(v)?;
    }
    Ok(())
}

fn read_u32_vec<R: Read>(
    r: &mut R,
    limits: ProgramReadLimits,
    table: &str,
) -> eyre::Result<Vec<u32>> {
    let len = checked_count::<u32>(r.read_u64::<LittleEndian>()?, limits, table)?;
    (0..len)
        .map(|_| Ok(r.read_u32::<LittleEndian>()?))
        .collect()
}

impl PrecomputeKind {
    fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        match self {
            PrecomputeKind::Poseidon2 { t } => {
                w.write_u8(0)?;
                w.write_u32::<LittleEndian>(*t as u32)?;
            }
            PrecomputeKind::Num2Bits { n } => {
                w.write_u8(1)?;
                w.write_u32::<LittleEndian>(*n as u32)?;
            }
            PrecomputeKind::IsZero => w.write_u8(2)?,
            PrecomputeKind::AliasCheck => w.write_u8(3)?,
            PrecomputeKind::Reveal { n } => {
                w.write_u8(5)?;
                w.write_u32::<LittleEndian>(*n as u32)?;
            }
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Ok(match r.read_u8()? {
            0 => PrecomputeKind::Poseidon2 {
                t: r.read_u32::<LittleEndian>()? as usize,
            },
            1 => PrecomputeKind::Num2Bits {
                n: r.read_u32::<LittleEndian>()? as usize,
            },
            2 => PrecomputeKind::IsZero,
            3 => PrecomputeKind::AliasCheck,
            5 => PrecomputeKind::Reveal {
                n: r.read_u32::<LittleEndian>()? as usize,
            },
            other => eyre::bail!("unknown PrecomputeKind tag {other}"),
        })
    }
}

impl BatchKind {
    fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        match self {
            BatchKind::Precompute(kind) => {
                w.write_u8(0)?;
                kind.write(w)?;
            }
            BatchKind::IsZeroReveal => w.write_u8(1)?,
            BatchKind::InjectedPoseidon2 { t } => {
                w.write_u8(2)?;
                w.write_u32::<LittleEndian>(*t as u32)?;
            }
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Ok(match r.read_u8()? {
            0 => BatchKind::Precompute(PrecomputeKind::read(r)?),
            1 => BatchKind::IsZeroReveal,
            2 => BatchKind::InjectedPoseidon2 {
                t: r.read_u32::<LittleEndian>()? as usize,
            },
            other => eyre::bail!("unknown BatchKind tag {other}"),
        })
    }
}

impl Program {
    /// Serializes this program. See the module doc for the exact format.
    pub fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        self.validate_encoding()?;
        w.write_all(MAGIC)?;
        w.write_u32::<LittleEndian>(VERSION)?;

        // instructions: fixed 16-byte records (1 opcode byte + 3 padding + three u32s).
        w.write_u64::<LittleEndian>(self.instructions.len() as u64)?;
        for instr in &self.instructions {
            w.write_u8(instr.op.to_u8())?;
            w.write_all(&[0u8; 3])?;
            w.write_u32::<LittleEndian>(instr.dst)?;
            w.write_u32::<LittleEndian>(instr.a)?;
            w.write_u32::<LittleEndian>(instr.b)?;
        }

        // constants: the one field-element table, via ark_serialize.
        w.write_u64::<LittleEndian>(self.constants.len() as u64)?;
        for c in &self.constants {
            c.serialize_compressed(&mut *w)?;
        }

        w.write_u64::<LittleEndian>(self.input_domains.len() as u64)?;
        for bank in &self.input_domains {
            w.write_u8(bank.to_u8())?;
        }

        w.write_u64::<LittleEndian>(self.inputs.len() as u64)?;
        for binding in &self.inputs {
            w.write_u8(binding.bank.to_u8())?;
            w.write_u32::<LittleEndian>(binding.slot)?;
            w.write_u32::<LittleEndian>(binding.input_index)?;
        }

        w.write_u64::<LittleEndian>(self.rounds.len() as u64)?;
        for round in &self.rounds {
            w.write_u32::<LittleEndian>(round.operand_start)?;
            w.write_u32::<LittleEndian>(round.len)?;
            w.write_u32::<LittleEndian>(round.result_start)?;
        }
        write_u32_vec(w, &self.round_operands)?;
        write_u32_vec(w, &self.round_results)?;

        w.write_u64::<LittleEndian>(self.precompute_batches.len() as u64)?;
        for batch in &self.precompute_batches {
            batch.kind.write(w)?;
            w.write_u64::<LittleEndian>(batch.sites as u64)?;
            // Banked, like a `WitnessSource::Slot` - a site input may be a `Public` slot (a literal the circuit
            // passed to the gadget), not only a share. See `SiteInput`.
            w.write_u64::<LittleEndian>(batch.input_slots.len() as u64)?;
            for input in &batch.input_slots {
                w.write_u8(input.bank.to_u8())?;
                w.write_u32::<LittleEndian>(input.slot)?;
            }
            write_u32_vec(w, &batch.result_requests)?;
            write_u32_vec(w, &batch.result_offsets)?;
            w.write_u64::<LittleEndian>(batch.result_targets.len() as u64)?;
            for target in &batch.result_targets {
                w.write_u8(target.bank.to_u8())?;
                w.write_u32::<LittleEndian>(target.slot)?;
            }
        }

        w.write_u64::<LittleEndian>(self.witness_sources.len() as u64)?;
        for source in &self.witness_sources {
            match *source {
                WitnessSource::One => w.write_u8(0)?,
                WitnessSource::Zero => w.write_u8(3)?,
                WitnessSource::Input(input) => {
                    w.write_u8(1)?;
                    w.write_u32::<LittleEndian>(input)?;
                }
                WitnessSource::Slot { bank, slot } => {
                    w.write_u8(2)?;
                    w.write_u8(bank.to_u8())?;
                    w.write_u32::<LittleEndian>(slot)?;
                }
            }
        }

        w.write_u64::<LittleEndian>(self.num_inputs as u64)?;

        w.write_u32::<LittleEndian>(self.slots.public)?;
        w.write_u32::<LittleEndian>(self.slots.shared)?;
        w.write_u32::<LittleEndian>(self.slots.local)?;

        Ok(())
    }

    /// Deserializes a program written by [`Program::write`].
    pub fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Self::read_with_limits(r, ProgramReadLimits::default())
    }

    pub fn read_exact<R: Read>(r: &mut R) -> eyre::Result<Self> {
        let program = Self::read(r)?;
        let mut trailing = [0u8; 1];
        eyre::ensure!(r.read(&mut trailing)? == 0, "trailing bytes after program");
        Ok(program)
    }

    pub fn read_with_limits<R: Read>(r: &mut R, limits: ProgramReadLimits) -> eyre::Result<Self> {
        let mut limited = r.take(limits.max_serialized_bytes.saturating_add(1));
        let r = &mut limited;
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        eyre::ensure!(
            &magic == MAGIC,
            "not a circom-mpc-compiler program (bad magic)"
        );
        let version = r.read_u32::<LittleEndian>()?;
        eyre::ensure!(
            version == VERSION,
            "unsupported program format version {version}"
        );

        let instr_count =
            checked_count::<Instruction>(r.read_u64::<LittleEndian>()?, limits, "instruction")?;
        let mut instructions = Vec::with_capacity(instr_count);
        for _ in 0..instr_count {
            let op = Opcode::from_u8(r.read_u8()?)?;
            let mut pad = [0u8; 3];
            r.read_exact(&mut pad)?;
            eyre::ensure!(pad == [0; 3], "instruction padding must be zero");
            let dst = r.read_u32::<LittleEndian>()?;
            let a = r.read_u32::<LittleEndian>()?;
            let b = r.read_u32::<LittleEndian>()?;
            instructions.push(Instruction { op, dst, a, b });
        }

        let const_count = checked_count::<Fr>(r.read_u64::<LittleEndian>()?, limits, "constant")?;
        let mut constants = Vec::with_capacity(const_count);
        for _ in 0..const_count {
            constants.push(Fr::deserialize_compressed(&mut *r)?);
        }

        let domain_count =
            checked_count::<Bank>(r.read_u64::<LittleEndian>()?, limits, "input domain")?;
        let mut input_domains = Vec::with_capacity(domain_count);
        for _ in 0..domain_count {
            input_domains.push(Bank::from_u8(r.read_u8()?)?);
        }

        let binding_count =
            checked_count::<InputBinding>(r.read_u64::<LittleEndian>()?, limits, "input binding")?;
        let mut inputs = Vec::with_capacity(binding_count);
        for _ in 0..binding_count {
            let bank = Bank::from_u8(r.read_u8()?)?;
            let slot = r.read_u32::<LittleEndian>()?;
            let input_index = r.read_u32::<LittleEndian>()?;
            inputs.push(InputBinding {
                bank,
                slot,
                input_index,
            });
        }

        let round_count =
            checked_count::<RoundEntry>(r.read_u64::<LittleEndian>()?, limits, "round")?;
        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            let operand_start = r.read_u32::<LittleEndian>()?;
            let len = r.read_u32::<LittleEndian>()?;
            let result_start = r.read_u32::<LittleEndian>()?;
            rounds.push(RoundEntry {
                operand_start,
                len,
                result_start,
            });
        }
        let round_operands = read_u32_vec(r, limits, "round operand")?;
        let round_results = read_u32_vec(r, limits, "round result")?;

        let batch_count = checked_count::<PrecomputeBatch>(
            r.read_u64::<LittleEndian>()?,
            limits,
            "precompute batch",
        )?;
        let mut batches = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            let kind = BatchKind::read(r)?;
            let sites =
                checked_count::<()>(r.read_u64::<LittleEndian>()?, limits, "precompute site")?;
            eyre::ensure!(sites > 0, "precompute batch has no sites");
            let input_count = checked_count::<SiteInput>(
                r.read_u64::<LittleEndian>()?,
                limits,
                "precompute input",
            )?;
            let mut input_slots = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                let bank = Bank::from_u8(r.read_u8()?)?;
                eyre::ensure!(bank != Bank::Local, "precompute input bank cannot be Local");
                let slot = r.read_u32::<LittleEndian>()?;
                input_slots.push(SiteInput { bank, slot });
            }
            let result_requests = read_u32_vec(r, limits, "precompute result request")?;
            let result_offsets = read_u32_vec(r, limits, "precompute result offset")?;
            let target_count = checked_count::<ResultTarget>(
                r.read_u64::<LittleEndian>()?,
                limits,
                "precompute target",
            )?;
            let mut result_targets = Vec::with_capacity(target_count);
            for _ in 0..target_count {
                let bank = Bank::from_u8(r.read_u8()?)?;
                eyre::ensure!(
                    bank != Bank::Local,
                    "precompute result bank cannot be Local"
                );
                let slot = r.read_u32::<LittleEndian>()?;
                result_targets.push(ResultTarget { bank, slot });
            }
            let expected_offsets = sites
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("precompute batch site count overflows"))?;
            eyre::ensure!(
                result_offsets.len() == expected_offsets,
                "precompute batch result_offsets has {} entries, expected sites + 1 = {}",
                result_offsets.len(),
                expected_offsets
            );
            eyre::ensure!(
                result_requests.len() == result_targets.len(),
                "precompute batch result_requests ({}) and result_targets ({}) must have the same \
                 length - one destination per requested slot",
                result_requests.len(),
                result_targets.len()
            );
            eyre::ensure!(
                result_offsets.first() == Some(&0)
                    && result_offsets.last().copied() == Some(result_requests.len() as u32)
                    && result_offsets.windows(2).all(|w| w[0] <= w[1]),
                "precompute batch has invalid CSR result offsets"
            );
            batches.push(PrecomputeBatch {
                kind,
                sites,
                input_slots,
                result_requests,
                result_offsets,
                result_targets,
            });
        }

        let witness_count = checked_count::<WitnessSource>(
            r.read_u64::<LittleEndian>()?,
            limits,
            "witness source",
        )?;
        let mut witness_sources = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            let source = match r.read_u8()? {
                0 => WitnessSource::One,
                1 => WitnessSource::Input(r.read_u32::<LittleEndian>()?),
                2 => WitnessSource::Slot {
                    bank: Bank::from_u8(r.read_u8()?)?,
                    slot: r.read_u32::<LittleEndian>()?,
                },
                3 => WitnessSource::Zero,
                other => eyre::bail!("unknown WitnessSource tag {other}"),
            };
            if let WitnessSource::Slot { bank, .. } = source {
                eyre::ensure!(bank != Bank::Local, "witness source bank cannot be Local");
            }
            witness_sources.push(source);
        }

        let num_inputs = checked_count::<()>(r.read_u64::<LittleEndian>()?, limits, "input")?;

        let public = r.read_u32::<LittleEndian>()?;
        let shared = r.read_u32::<LittleEndian>()?;
        let local = r.read_u32::<LittleEndian>()?;

        let program = Program {
            instructions,
            constants,
            input_domains,
            inputs,
            rounds,
            round_operands,
            round_results,
            precompute_batches: batches,
            witness_sources,
            num_inputs,
            slots: SlotCounts {
                public,
                shared,
                local,
            },
        };
        program.validate_encoding()?;
        eyre::ensure!(limited.limit() > 0, "serialized program exceeds byte limit");
        Ok(program)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::vm::driver::plain::PlainDriver;
    use crate::vm::Machine;
    use crate::{CoCircomCompiler, CompilerConfig};

    /// Compiles one fixture through the public path used by serialized programs.
    fn program(circuit: &str) -> super::Program {
        let root = env!("CARGO_MANIFEST_DIR");
        let mut config = CompilerConfig::default();
        config
            .link_library
            .push(format!("{root}/circuits/libs/").into());
        CoCircomCompiler::compile(format!("{root}/circuits/{circuit}.circom"), config).unwrap()
    }

    fn witness(program: &super::Program, inputs: &[Fr]) -> Vec<Fr> {
        let inputs = program.classify_inputs(inputs, |v| v).unwrap();
        let mut driver = PlainDriver;
        Machine::run(program, &mut driver, &inputs).unwrap()
    }

    #[test]
    fn round_trips_a_program_with_a_round_byte_identically() {
        let original = program("multiplier2");
        assert_eq!(
            original.witness_sources.first(),
            Some(&super::WitnessSource::One)
        );
        assert!(original
            .witness_sources
            .iter()
            .any(|source| matches!(source, super::WitnessSource::Input(_))));
        assert!(original
            .witness_sources
            .iter()
            .any(|source| matches!(source, super::WitnessSource::Slot { .. })));
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();

        let inputs = [Fr::from(5u64), Fr::from(10u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn round_trips_a_program_with_a_precompute_site_byte_identically() {
        let original = program("precomputation_iszero_test");
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();

        let inputs = [Fr::from(0u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn round_trips_an_unbound_zero_witness_source() {
        let original = program("loop_unrolling");
        assert!(original
            .witness_sources
            .contains(&super::WitnessSource::Zero));
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();
        assert!(read_back
            .witness_sources
            .contains(&super::WitnessSource::Zero));

        let inputs: Vec<_> = (1..=original.num_inputs)
            .map(|i| Fr::from(i as u64))
            .collect();
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn round_trips_a_fused_iszero_reveal_batch() {
        let original = program("precomputation_iszero_reveal_test");
        assert_eq!(original.precompute_batches.len(), 1);
        assert_eq!(
            original.precompute_batches[0].kind,
            super::BatchKind::IsZeroReveal
        );
        assert_eq!(original.precompute_batches[0].sites, 2);
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();

        assert_eq!(
            read_back.precompute_batches[0].kind,
            super::BatchKind::IsZeroReveal
        );
        assert_eq!(read_back.precompute_batches[0].sites, 2);
        let inputs = [Fr::from(0u64), Fr::from(7u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn round_trips_a_fused_isequal_reveal_batch() {
        let original = program("precomputation_isequal_reveal_test");
        assert_eq!(original.precompute_batches.len(), 1);
        assert_eq!(
            original.precompute_batches[0].kind,
            super::BatchKind::IsZeroReveal
        );
        assert_eq!(original.precompute_batches[0].sites, 3);
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();

        assert_eq!(
            read_back.precompute_batches[0].kind,
            super::BatchKind::IsZeroReveal
        );
        assert_eq!(read_back.precompute_batches[0].sites, 3);
        let inputs = [Fr::from(10u64), Fr::from(4u64), Fr::from(7u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn round_trips_a_public_precompute_batch() {
        let original = program("precomputation_public_test");
        assert!(original
            .precompute_batches
            .iter()
            .flat_map(|batch| &batch.result_targets)
            .all(|target| target.bank == super::Bank::Public));
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();
        assert!(read_back
            .precompute_batches
            .iter()
            .flat_map(|batch| &batch.result_targets)
            .all(|target| target.bank == super::Bank::Public));
        let inputs = [Fr::from(0u64), Fr::from(9u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    /// The two single-site programs above both have exactly one batch, so they can't catch a bug in
    /// how *multiple* batches or their `Opcode::Precompute` instructions round-trip. This one is
    /// genuinely staged: two same-kind sites at different stages, hence two batches interleaved into
    /// the stream (see `circuits/precomputation_staged_test.circom`).
    #[test]
    fn round_trips_a_staged_multi_batch_program() {
        let original = program("precomputation_staged_test");
        assert_eq!(
            original.precompute_batches.len(),
            2,
            "fixture must be staged for this test to cover anything"
        );
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let read_back = super::Program::read(&mut bytes.as_slice()).unwrap();

        assert_eq!(read_back.precompute_batches.len(), 2);
        assert_eq!(
            read_back
                .instructions
                .iter()
                .filter(|i| i.op == super::Opcode::Precompute)
                .count(),
            2
        );
        let inputs = [Fr::from(3u64), Fr::from(5u64)];
        assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
    }

    #[test]
    fn read_rejects_bad_magic() {
        let err = super::Program::read(&mut [0u8; 16].as_slice()).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");
    }

    #[test]
    fn validation_rejects_out_of_range_witness_and_batch_targets() {
        let mut invalid_witness = program("multiplier2");
        invalid_witness.witness_sources[1] = super::WitnessSource::Slot {
            bank: super::Bank::Shared,
            slot: invalid_witness.slots.shared,
        };
        assert!(invalid_witness.validate_encoding().is_err());
        assert!(invalid_witness.write(&mut Vec::new()).is_err());

        let mut invalid_batch = program("precomputation_iszero_test");
        invalid_batch.precompute_batches[0].result_targets[0].slot = invalid_batch.slots.shared;
        assert!(invalid_batch.validate_encoding().is_err());

        let mut invalid_poseidon = program("precomputation_poseidon2_test");
        invalid_poseidon.precompute_batches[0].kind =
            super::BatchKind::Precompute(crate::ir::PrecomputeKind::Poseidon2 { t: 5 });
        assert!(invalid_poseidon.validate_encoding().is_err());
    }
}
