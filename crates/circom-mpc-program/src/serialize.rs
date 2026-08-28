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

use crate::{
    BatchIdx, GadgetBatch, GadgetKind, Bank, BatchKind, InputBinding, InputIdx, Instruction,
    Opcode, Poseidon2Width, Program, ResultSlot, ResultTarget, RoundEntry, RoundIdx, SiteInput,
    Slot, SlotCounts, WitnessSource,
};

/// A wire-format index newtype: a thin, checked wrapper over `u32`. Lets [`write_index_vec`]/
/// [`read_index_vec`] serve every index role ([`Slot`], [`ResultSlot`]) with one implementation.
trait WireIndex: Copy {
    fn to_u32(self) -> u32;
    fn from_u32(raw: u32) -> Self;
}

impl WireIndex for Slot {
    fn to_u32(self) -> u32 {
        self.get()
    }

    fn from_u32(raw: u32) -> Self {
        Slot::new(raw)
    }
}

impl WireIndex for ResultSlot {
    fn to_u32(self) -> u32 {
        self.get()
    }

    fn from_u32(raw: u32) -> Self {
        ResultSlot::new(raw)
    }
}

const MAGIC: &[u8; 8] = b"CMPCVM\0\0";
/// Bumped on every layout change; `read` rejects anything else. Deliberately no compatibility
/// shim: accepting an older layout could produce a plausible-looking wrong witness.
const VERSION: u32 = 2;

/// Caps [`Program::read`] enforces against an untrusted or corrupted input before it allocates
/// anything, so a malformed length field can't drive an unbounded allocation.
#[derive(Clone, Copy, Debug)]
pub struct ProgramReadLimits {
    /// Maximum number of bytes `read` will consume from the source.
    pub max_serialized_bytes: u64,
    /// Maximum total bytes any single table is allowed to pre-allocate for.
    pub max_estimated_allocation: usize,
    /// Maximum number of entries any single table may declare.
    pub max_table_entries: usize,
}

impl Default for ProgramReadLimits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 256 * 1024 * 1024,
            max_estimated_allocation: 256 * 1024 * 1024,
            max_table_entries: 0x0100_0000,
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
            Opcode::Gadget => 11,
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
            11 => Opcode::Gadget,
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

/// Writes a length prefix as the wire format's `u64` count field.
fn write_len<W: Write>(w: &mut W, n: usize) -> eyre::Result<()> {
    Ok(w.write_u64::<LittleEndian>(n as u64)?)
}

fn write_u32_vec<W: Write>(w: &mut W, values: &[u32]) -> eyre::Result<()> {
    write_len(w, values.len())?;
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

fn write_index_vec<W: Write, T: WireIndex>(w: &mut W, values: &[T]) -> eyre::Result<()> {
    write_len(w, values.len())?;
    for &v in values {
        w.write_u32::<LittleEndian>(v.to_u32())?;
    }
    Ok(())
}

fn read_index_vec<R: Read, T: WireIndex>(
    r: &mut R,
    limits: ProgramReadLimits,
    table: &str,
) -> eyre::Result<Vec<T>> {
    let len = checked_count::<u32>(r.read_u64::<LittleEndian>()?, limits, table)?;
    (0..len)
        .map(|_| Ok(T::from_u32(r.read_u32::<LittleEndian>()?)))
        .collect()
}

impl GadgetKind {
    fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        match self {
            GadgetKind::Poseidon2 { t } => {
                w.write_u8(0)?;
                w.write_u32::<LittleEndian>(t.as_u32())?;
            }
            GadgetKind::Num2Bits { n } => {
                w.write_u8(1)?;
                w.write_u32::<LittleEndian>(
                    u32::try_from(*n).map_err(|_| eyre::eyre!("Num2Bits n exceeds u32"))?,
                )?;
            }
            GadgetKind::IsZero => w.write_u8(2)?,
            GadgetKind::AliasCheck => w.write_u8(3)?,
            GadgetKind::Reveal { n } => {
                w.write_u8(5)?;
                w.write_u32::<LittleEndian>(
                    u32::try_from(*n).map_err(|_| eyre::eyre!("Reveal n exceeds u32"))?,
                )?;
            }
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Ok(match r.read_u8()? {
            0 => GadgetKind::Poseidon2 {
                t: Poseidon2Width::from_u32(r.read_u32::<LittleEndian>()?)?,
            },
            1 => GadgetKind::Num2Bits {
                n: r.read_u32::<LittleEndian>()? as usize,
            },
            2 => GadgetKind::IsZero,
            3 => GadgetKind::AliasCheck,
            5 => GadgetKind::Reveal {
                n: r.read_u32::<LittleEndian>()? as usize,
            },
            other => eyre::bail!("unknown GadgetKind tag {other}"),
        })
    }
}

impl BatchKind {
    fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        match self {
            BatchKind::Gadget(kind) => {
                w.write_u8(0)?;
                kind.write(w)?;
            }
            BatchKind::IsZeroReveal => w.write_u8(1)?,
            BatchKind::PrecomputedPoseidon2 { t } => {
                w.write_u8(2)?;
                w.write_u32::<LittleEndian>(t.as_u32())?;
            }
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Ok(match r.read_u8()? {
            0 => BatchKind::Gadget(GadgetKind::read(r)?),
            1 => BatchKind::IsZeroReveal,
            2 => BatchKind::PrecomputedPoseidon2 {
                t: Poseidon2Width::from_u32(r.read_u32::<LittleEndian>()?)?,
            },
            other => eyre::bail!("unknown BatchKind tag {other}"),
        })
    }
}

impl Program {
    /// Serializes this program. See the module doc for the exact format.
    ///
    /// # Errors
    ///
    /// Returns an error if the program fails [`Program::validate_encoding`], or if writing to
    /// `w` fails.
    pub fn write<W: Write>(&self, w: &mut W) -> eyre::Result<()> {
        self.validate_encoding()?;
        w.write_all(MAGIC)?;
        w.write_u32::<LittleEndian>(VERSION)?;

        // instructions: fixed 16-byte records (1 opcode byte + 3 padding + three u32s). The
        // table-index variants (`Reshare`/`Gadget`) write their index as `a`, leaving `dst`/`b`
        // zero - `Instruction::op` recovers the tag on read.
        write_len(w, self.instructions.len())?;
        for instr in &self.instructions {
            w.write_u8(instr.op().to_u8())?;
            w.write_all(&[0u8; 3])?;
            let (dst, a, b) = match *instr {
                Instruction::Arith { dst, a, b, .. } => (dst.get(), a.get(), b.get()),
                Instruction::Reshare(round_idx) => (0, round_idx.get(), 0),
                Instruction::Gadget(batch_idx) => (0, batch_idx.get(), 0),
            };
            w.write_u32::<LittleEndian>(dst)?;
            w.write_u32::<LittleEndian>(a)?;
            w.write_u32::<LittleEndian>(b)?;
        }

        // constants: the one field-element table, via ark_serialize.
        write_len(w, self.constants.len())?;
        for c in &self.constants {
            c.serialize_compressed(&mut *w)?;
        }

        write_len(w, self.input_domains.len())?;
        for bank in &self.input_domains {
            w.write_u8(bank.to_u8())?;
        }

        write_len(w, self.inputs.len())?;
        for binding in &self.inputs {
            w.write_u8(binding.bank.to_u8())?;
            w.write_u32::<LittleEndian>(binding.slot.get())?;
            w.write_u32::<LittleEndian>(binding.input_index.get())?;
        }

        write_len(w, self.rounds.len())?;
        for round in &self.rounds {
            w.write_u32::<LittleEndian>(round.operand_start)?;
            w.write_u32::<LittleEndian>(round.len)?;
            w.write_u32::<LittleEndian>(round.result_start)?;
        }
        write_index_vec(w, &self.round_operands)?;
        write_index_vec(w, &self.round_results)?;

        write_len(w, self.gadget_batches.len())?;
        for batch in &self.gadget_batches {
            batch.kind.write(w)?;
            write_len(w, batch.sites)?;
            // Banked, like a `WitnessSource::Slot` - a site input may be a `Public` slot (a literal the circuit
            // passed to the gadget), not only a share. See `SiteInput`.
            write_len(w, batch.input_slots.len())?;
            for input in &batch.input_slots {
                w.write_u8(input.bank.to_u8())?;
                w.write_u32::<LittleEndian>(input.slot.get())?;
            }
            write_index_vec(w, &batch.result_requests)?;
            write_u32_vec(w, &batch.result_offsets)?;
            write_len(w, batch.result_targets.len())?;
            for target in &batch.result_targets {
                w.write_u8(target.bank.to_u8())?;
                w.write_u32::<LittleEndian>(target.slot.get())?;
            }
        }

        write_len(w, self.witness_sources.len())?;
        for source in &self.witness_sources {
            match *source {
                WitnessSource::One => w.write_u8(0)?,
                WitnessSource::Zero => w.write_u8(3)?,
                WitnessSource::Input(input) => {
                    w.write_u8(1)?;
                    w.write_u32::<LittleEndian>(input.get())?;
                }
                WitnessSource::Slot { bank, slot } => {
                    w.write_u8(2)?;
                    w.write_u8(bank.to_u8())?;
                    w.write_u32::<LittleEndian>(slot.get())?;
                }
            }
        }

        write_len(w, self.num_inputs)?;

        w.write_u32::<LittleEndian>(self.slots.public)?;
        w.write_u32::<LittleEndian>(self.slots.shared)?;
        w.write_u32::<LittleEndian>(self.slots.local)?;

        Ok(())
    }

    /// Deserializes a program written by [`Program::write`].
    ///
    /// # Errors
    ///
    /// Returns an error if `r` doesn't hold a validly-encoded program, or reading from `r` fails.
    pub fn read<R: Read>(r: &mut R) -> eyre::Result<Self> {
        Self::read_with_limits(r, ProgramReadLimits::default())
    }

    /// Like [`Program::read`], but also rejects any trailing bytes left in `r` after the program.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Program::read`], or if `r` has trailing
    /// bytes after the program.
    pub fn read_exact<R: Read>(r: &mut R) -> eyre::Result<Self> {
        let program = Self::read(r)?;
        let mut trailing = [0u8; 1];
        eyre::ensure!(r.read(&mut trailing)? == 0, "trailing bytes after program");
        Ok(program)
    }

    /// Like [`Program::read`], but with caller-supplied resource limits instead of
    /// [`ProgramReadLimits::default`].
    ///
    /// # Errors
    ///
    /// Returns an error if `r` doesn't hold a validly-encoded program, if any table exceeds
    /// `limits`, or reading from `r` fails.
    #[allow(
        clippy::too_many_lines,
        reason = "a single sequential deserialization pass mirroring Program::write's field order; splitting it would not improve clarity"
    )]
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
            instructions.push(match op {
                Opcode::Reshare => Instruction::Reshare(RoundIdx::new(a)),
                Opcode::Gadget => Instruction::Gadget(BatchIdx::new(a)),
                op => Instruction::Arith {
                    op,
                    dst: Slot::new(dst),
                    a: Slot::new(a),
                    b: Slot::new(b),
                },
            });
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
            let slot = Slot::new(r.read_u32::<LittleEndian>()?);
            let input_index = InputIdx::new(r.read_u32::<LittleEndian>()?);
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
        let round_operands = read_index_vec(r, limits, "round operand")?;
        let round_results = read_index_vec(r, limits, "round result")?;

        let batch_count = checked_count::<GadgetBatch>(
            r.read_u64::<LittleEndian>()?,
            limits,
            "gadget batch",
        )?;
        let mut batches = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            let kind = BatchKind::read(r)?;
            let sites =
                checked_count::<()>(r.read_u64::<LittleEndian>()?, limits, "gadget site")?;
            eyre::ensure!(sites > 0, "gadget batch has no sites");
            let input_count = checked_count::<SiteInput>(
                r.read_u64::<LittleEndian>()?,
                limits,
                "gadget input",
            )?;
            let mut input_slots = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                let bank = Bank::from_u8(r.read_u8()?)?;
                eyre::ensure!(
                    bank != Bank::Local,
                    "gadget input bank cannot be Local"
                );
                let slot = Slot::new(r.read_u32::<LittleEndian>()?);
                input_slots.push(SiteInput { bank, slot });
            }
            let result_requests = read_index_vec::<_, ResultSlot>(r, limits, "gadget result request")?;
            let result_offsets = read_u32_vec(r, limits, "gadget result offset")?;
            let target_count = checked_count::<ResultTarget>(
                r.read_u64::<LittleEndian>()?,
                limits,
                "gadget target",
            )?;
            let mut result_targets = Vec::with_capacity(target_count);
            for _ in 0..target_count {
                let bank = Bank::from_u8(r.read_u8()?)?;
                eyre::ensure!(
                    bank != Bank::Local,
                    "gadget result bank cannot be Local"
                );
                let slot = Slot::new(r.read_u32::<LittleEndian>()?);
                result_targets.push(ResultTarget { bank, slot });
            }
            let expected_offsets = sites
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("gadget batch site count overflows"))?;
            eyre::ensure!(
                result_offsets.len() == expected_offsets,
                "gadget batch result_offsets has {} entries, expected sites + 1 = {}",
                result_offsets.len(),
                expected_offsets
            );
            eyre::ensure!(
                result_requests.len() == result_targets.len(),
                "gadget batch result_requests ({}) and result_targets ({}) must have the same \
                 length - one destination per requested slot",
                result_requests.len(),
                result_targets.len()
            );
            let result_request_count = u32::try_from(result_requests.len())
                .map_err(|_| eyre::eyre!("gadget batch has too many result requests"))?;
            eyre::ensure!(
                result_offsets.first() == Some(&0)
                    && result_offsets.last().copied() == Some(result_request_count)
                    && result_offsets.windows(2).all(|w| w[0] <= w[1]),
                "gadget batch has invalid CSR result offsets"
            );
            batches.push(GadgetBatch {
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
                1 => WitnessSource::Input(InputIdx::new(r.read_u32::<LittleEndian>()?)),
                2 => WitnessSource::Slot {
                    bank: Bank::from_u8(r.read_u8()?)?,
                    slot: Slot::new(r.read_u32::<LittleEndian>()?),
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
            gadget_batches: batches,
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
    #[test]
    fn read_rejects_bad_magic() {
        let err = super::Program::read(&mut [0u8; 16].as_slice())
            .expect_err("all-zero bytes are not a valid magic");
        assert!(err.to_string().contains("bad magic"), "{err}");
    }
}
