#![allow(dead_code)]

use ark_ff::BigInteger;
use ark_serialize::SerializationError;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io;
use std::io::Read;
use std::marker::PhantomData;
use std::str::FromStr;
use std::str::Utf8Error;
use thiserror::Error;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{PrimeField, Zero};
use rayon::prelude::*;
use serde::ser::SerializeSeq;
use serde::{de, Serializer};

const WITNESS_HEADER: &str = "wtns";
const MAX_VERSION: u32 = 2;
const N_SECTIONS: u32 = 2;

/// Error type describing errors during parsing witness files
#[derive(Debug, Error)]
pub enum WitnessParserError {
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] io::Error),
    /// Error during serialization
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// Error describing that the version of the file is not supported for parsing
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    /// Error describing that the number of sections in the file is invalid
    #[error("Wrong number of sections is {0}, but got {1}")]
    InvalidSectionNumber(u32, u32),
    /// Error describing that the ScalarField from curve does not match in witness file
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
    /// Error during reading circom file header
    #[error(transparent)]
    WrongHeader(#[from] InvalidHeaderError),
}

/// Error type describing errors during reading circom file headers
#[derive(Debug, Error)]
pub enum InvalidHeaderError {
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// File header is not valid UTF-8
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
    /// File header does not match the expected header
    #[error("Wrong header. Expected {0} but got {1}")]
    WrongHeader(String, String),
}

pub(crate) fn read_header<R: Read>(
    mut reader: R,
    should_header: &str,
) -> std::result::Result<(), InvalidHeaderError> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf)?;
    let is_header = std::str::from_utf8(&buf[..])?;
    if is_header == should_header {
        Ok(())
    } else {
        Err(InvalidHeaderError::WrongHeader(
            should_header.to_owned(),
            is_header.to_owned(),
        ))
    }
}

/// Represents a witness in the format defined by circom. Implements [`Witness::from_reader`] to deserialize a witness from a reader.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Witness<F> {
    /// The values of the witness as [`CircomArkworksPrimeFieldBridge`] elements
    pub values: Vec<F>,
}

impl<F: CircomArkworksPrimeFieldBridge> Witness<F> {
    /// Deserializes a [`Witness`] from a reader.
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, WitnessParserError> {
        tracing::trace!("trying to read witness");
        read_header(&mut reader, WITNESS_HEADER)?;
        let version = reader.read_u32::<LittleEndian>()?;
        if version > MAX_VERSION {
            return Err(WitnessParserError::VersionNotSupported(
                MAX_VERSION,
                version,
            ));
        }

        let n_sections = reader.read_u32::<LittleEndian>()?;
        if n_sections > N_SECTIONS {
            return Err(WitnessParserError::InvalidSectionNumber(
                N_SECTIONS, n_sections,
            ));
        }
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        let n8 = reader.read_u32::<LittleEndian>()?;
        let mut buf = vec![0; usize::try_from(n8).expect("u32 fits into usize")];
        reader.read_exact(buf.as_mut_slice())?;
        if F::MODULUS.to_bytes_le() != buf {
            tracing::trace!("wrong scalar field");
            return Err(WitnessParserError::WrongScalarField);
        }
        let n_witness = reader.read_u32::<LittleEndian>()?;
        //this is the section id and length
        //don't know if we need them, maybe at least log them later
        let _ = reader.read_u32::<LittleEndian>()?;
        let _ = reader.read_u64::<LittleEndian>()?;
        Ok(Self {
            values: (0..n_witness)
                .map(|_| {
                    F::from_reader(&mut reader).map_err(WitnessParserError::SerializationError)
                })
                .collect::<Result<Vec<F>, _>>()?,
        })
    }
}

type IoResult<T> = Result<T, SerializationError>;

macro_rules! impl_bn256 {
    () => {
        //TODO use stringify
        impl_serde_for_curve!(bn254, Bn254, ark_bn254, "bn254", 32, 32, "bn128");
    };
}

macro_rules! impl_serde_for_curve {
    ($mod_name: ident, $config: ident, $curve: ident, $name: expr, $field_size: expr, $scalar_field_size: expr, $circom_name: expr) => {

mod $mod_name {

    use $curve::{$config, Fq, Fq2, Fr};
    use ark_ff::BigInt;
    use ark_serialize::{CanonicalDeserialize, SerializationError};
    use serde::ser::SerializeSeq;

    use super::*;
        impl CircomArkworksPrimeFieldBridge for Fr {
            const SERIALIZED_BYTE_SIZE: usize = $scalar_field_size;
            #[inline]
            fn from_reader(mut reader: impl Read) -> IoResult<Self> {
                let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
                reader.read_exact(&mut buf[..])?;
                Ok(Self::from_le_bytes_mod_order(&buf))
            }

            #[inline]
            fn montgomery_bigint_from_reader(mut reader: impl Read) -> IoResult<Self> {
                let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
                reader.read_exact(&mut buf[..])?;
                Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                    buf.as_slice(),
                )?))
            }
            #[inline]
            fn from_reader_for_groth16_zkey(reader: impl Read) -> IoResult<Self> {
                Ok(Self::new_unchecked(Self::montgomery_bigint_from_reader(reader)?.into_bigint()))
            }

        }
        impl CircomArkworksPrimeFieldBridge for Fq {
            const SERIALIZED_BYTE_SIZE: usize = $field_size;
            #[inline]
            fn from_reader(mut reader: impl Read) -> IoResult<Self> {
                let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
                reader.read_exact(&mut buf[..])?;
                Ok(Self::from_le_bytes_mod_order(&buf))
            }

            #[inline]
            fn montgomery_bigint_from_reader(mut reader: impl Read) -> IoResult<Self> {
                let mut buf = [0u8; Self::SERIALIZED_BYTE_SIZE];
                reader.read_exact(&mut buf[..])?;
                Ok(Self::new_unchecked(BigInt::deserialize_uncompressed(
                    buf.as_slice(),
                )?))
            }
            #[inline]
            fn from_reader_for_groth16_zkey(reader: impl Read) -> IoResult<Self> {
                Ok(Self::new_unchecked(Self::montgomery_bigint_from_reader(reader)?.into_bigint()))
            }
        }

        impl CircomArkworksPairingBridge for $config {
            const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = $field_size;
            const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = $field_size * 2;
            const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = $field_size * 2;
            const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = $field_size * 2 * 2;
            const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
            const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

            fn get_circom_name() -> String {
                $circom_name.to_owned()
            }

            //Circom serializes its field elements in montgomery form
            //therefore we use Fq::montgomery_bigint_from_reader
            fn g1_from_bytes(bytes: &[u8]) -> IoResult<Self::G1Affine> {
                //already in montgomery form
                let x = Fq::montgomery_bigint_from_reader(&bytes[..Fq::SERIALIZED_BYTE_SIZE])?;
                let y = Fq::montgomery_bigint_from_reader(&bytes[Fq::SERIALIZED_BYTE_SIZE..])?;

                if x.is_zero() && y.is_zero() {
                    return Ok(Self::G1Affine::zero());
                }

                let p = Self::G1Affine::new_unchecked(x, y);

                if !p.is_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                Ok(p)
            }

            fn g2_from_bytes(bytes: &[u8]) -> IoResult<Self::G2Affine> {
                //already in montgomery form
                let x0 = Fq::montgomery_bigint_from_reader(&bytes[..Fq::SERIALIZED_BYTE_SIZE])?;
                let x1 = Fq::montgomery_bigint_from_reader(
                    &bytes[Fq::SERIALIZED_BYTE_SIZE..Fq::SERIALIZED_BYTE_SIZE * 2],
                )?;
                let y0 = Fq::montgomery_bigint_from_reader(
                    &bytes[Fq::SERIALIZED_BYTE_SIZE * 2..Fq::SERIALIZED_BYTE_SIZE * 3],
                )?;
                let y1 = Fq::montgomery_bigint_from_reader(
                    &bytes[Fq::SERIALIZED_BYTE_SIZE * 3..Fq::SERIALIZED_BYTE_SIZE * 4],
                )?;

                let x = Fq2::new(x0, x1);
                let y = Fq2::new(y0, y1);

                if x.is_zero() && y.is_zero() {
                    return Ok(Self::G2Affine::zero());
                }

                let p = Self::G2Affine::new_unchecked(x, y);
                if !p.is_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                Ok(p)
            }

            fn g1_from_reader(mut reader: impl Read) -> IoResult<Self::G1Affine> {
                let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
                reader.read_exact(&mut buf)?;
                Self::g1_from_bytes(&buf)
            }

            fn g2_from_reader(mut reader: impl Read) -> IoResult<Self::G2Affine> {
                let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
                reader.read_exact(&mut buf)?;
                Self::g2_from_bytes(&buf)
            }

            fn g1_from_strings_projective(x: &str, y: &str, z: &str) -> IoResult<Self::G1Affine> {
                let x = parse_field(x)?;
                let y = parse_field(y)?;
                let z = parse_field(z)?;
                let p = Self::G1Affine::from($curve::G1Projective::new(x, y, z));
                if p.is_zero() {
                    return Ok(p);
                }
                if !p.is_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                Ok(p)
            }

            fn g1_to_strings_projective(p: &Self::G1Affine) -> Vec<String> {
                if let Some((x, y)) = p.xy() {
                    vec![x.to_string(), y.to_string(), "1".to_owned()]
                } else {
                    //point at infinity
                    vec!["0".to_owned(), "1".to_owned(), "0".to_owned()]
                }
            }

            fn g2_from_strings_projective(
                x0: &str,
                x1: &str,
                y0: &str,
                y1: &str,
                z0: &str,
                z1: &str,
            ) -> IoResult<Self::G2Affine> {
                let x0 = parse_field(x0)?;
                let x1 = parse_field(x1)?;
                let y0 = parse_field(y0)?;
                let y1 = parse_field(y1)?;
                let z0 = parse_field(z0)?;
                let z1 = parse_field(z1)?;

                let x = $curve::Fq2::new(x0, x1);
                let y = $curve::Fq2::new(y0, y1);
                let z = $curve::Fq2::new(z0, z1);
                let p = $curve::G2Affine::from($curve::G2Projective::new(x, y, z));
                if p.is_zero() {
                    return Ok(p);
                }
                if !p.is_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(SerializationError::InvalidData);
                }
                Ok(p)
            }

            fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error> {
                let (x, y) = p.xy().unwrap();
                let mut x_seq = ser.serialize_seq(Some(3))?;
                x_seq.serialize_element(&vec![x.c0.to_string(), x.c1.to_string()])?;
                x_seq.serialize_element(&vec![y.c0.to_string(), y.c1.to_string()])?;
                x_seq.serialize_element(&vec!["1", "0"])?;
                x_seq.end()
            }
            fn serialize_gt<S: Serializer>(
                p: &Self::TargetField,
                ser: S,
            ) -> Result<S::Ok, S::Error> {
                let a = p.c0;
                let b = p.c1;
                let aa = a.c0;
                let ab = a.c1;
                let ac = a.c2;
                let ba = b.c0;
                let bb = b.c1;
                let bc = b.c2;
                let a = vec![
                    vec![aa.c0.to_string(), aa.c1.to_string()],
                    vec![ab.c0.to_string(), ab.c1.to_string()],
                    vec![ac.c0.to_string(), ac.c1.to_string()],
                ];
                let b = vec![
                    vec![ba.c0.to_string(), ba.c1.to_string()],
                    vec![bb.c0.to_string(), bb.c1.to_string()],
                    vec![bc.c0.to_string(), bc.c1.to_string()],
                ];
                let mut seq = ser.serialize_seq(Some(2))?;
                seq.serialize_element(&a)?;
                seq.serialize_element(&b)?;
                seq.end()
            }
            fn serialize_fr<S: Serializer>(p: &Self::ScalarField, ser: S) -> Result<S::Ok, S::Error> {
                ser.serialize_str(&p.to_string())
                }

            fn deserialize_gt_element<'de, D>(
                deserializer: D,
            ) -> Result<Self::TargetField, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                deserializer.deserialize_seq(TargetGroupVisitor::<Self>::new())
            }

        }

    impl<'de> de::Visitor<'de> for TargetGroupVisitor<$config> {
        type Value = $curve::Fq12;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(
                &format!("An element of {}::Fq12 represented as string with radix 10. Must be a sequence of form [[[String; 2]; 3]; 2].", $name),
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let x = seq
                .next_element::<Vec<Vec<String>>>()?
                .ok_or(de::Error::custom(
                    &format!("expected elements target group in {} as sequence of sequences", $name),
                ))?;
            let y = seq
                .next_element::<Vec<Vec<String>>>()?
                .ok_or(de::Error::custom(
                    &format!("expected elements target group in {} as sequence of sequences", $name),
                ))?;
            if x.len() != 3 || y.len() != 3 {
                Err(de::Error::custom(
                    &format!("need three elements for cubic extension field in {}", $name),
                ))
            } else {
                let c0 = cubic_extension_field_from_vec(x).map_err(|_| {
                    de::Error::custom("InvalidData for target group (cubic extension field)")
                })?;
                let c1 = cubic_extension_field_from_vec(y).map_err(|_| {
                    de::Error::custom("InvalidData for target group (cubic extension field)")
                })?;
                Ok($curve::Fq12::new(c0, c1))
            }
        }
    }
    #[inline]
    fn cubic_extension_field_from_vec(strings: Vec<Vec<String>>) -> IoResult<$curve::Fq6> {
        if strings.len() != 3 {
            Err(SerializationError::InvalidData)
        } else {
            let c0 = quadratic_extension_field_from_vec(&strings[0])?;
            let c1 = quadratic_extension_field_from_vec(&strings[1])?;
            let c2 = quadratic_extension_field_from_vec(&strings[2])?;
            Ok($curve::Fq6::new(c0, c1, c2))
        }
    }
    #[inline]
    fn quadratic_extension_field_from_vec(strings: &[String]) -> IoResult<$curve::Fq2> {
        if strings.len() != 2 {
            Err(SerializationError::InvalidData)
        } else {
            let c0 = parse_field(&strings[0])?;
            let c1 = parse_field(&strings[1])?;
            Ok($curve::Fq2::new(c0, c1))
        }
    }

    #[inline]
    fn parse_field(string: &str) -> IoResult<$curve::Fq> {
        $curve::Fq::from_str(string).map_err(|_| SerializationError::InvalidData)
    }
}
    };
}
struct FrVisitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> FrVisitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for FrVisitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = P::ScalarField;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an element over a PrimeField as string with radix 10")
    }
    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        P::ScalarField::from_str(s).map_err(|_| de::Error::custom("invalid field element"))
    }
}
struct G1Visitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G1Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for G1Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = P::G1Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 3 strings, representing a projective point on G1")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else {
            P::g1_from_strings_projective(&x, &y, &z)
                .map_err(|_| de::Error::custom("Invalid projective point on G1.".to_owned()))
        }
    }
}

struct G2Visitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> TargetGroupVisitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl<'de, P: Pairing + CircomArkworksPairingBridge> de::Visitor<'de> for G2Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    type Value = P::G2Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("a sequence of 3 sequences, representing a projective point on G2. The 3 sequences each consist of two strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else if x.len() != 2 {
            Err(de::Error::custom(format!(
                "x coordinates need two field elements for G2, but got {}",
                x.len()
            )))
        } else if y.len() != 2 {
            Err(de::Error::custom(format!(
                "y coordinates need two field elements for G2, but got {}",
                y.len()
            )))
        } else if z.len() != 2 {
            Err(de::Error::custom(format!(
                "z coordinates need two field elements for G2, but got {}",
                z.len()
            )))
        } else {
            Ok(P::g2_from_strings_projective(&x[0], &x[1], &y[0], &y[1], &z[0], &z[1]).unwrap())
        }
    }
}

struct TargetGroupVisitor<P: Pairing + CircomArkworksPairingBridge>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> G2Visitor<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

/// Bridge trait to serialize and deserialize pairings contained in circom files into and from [`ark_ec::pairing::Pairing`] representation
pub trait CircomArkworksPairingBridge: Pairing
where
    Self::BaseField: CircomArkworksPrimeFieldBridge,
    Self::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Size of compressed element of G1 in bytes
    const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of G1 in bytes
    const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    /// Size of compressed element of G2 in bytes
    const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of G2 in bytes
    const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    /// Size of compressed element of Gt in bytes
    const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of Gt in bytes
    const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    /// Returns the name of the curve as defined in circom
    fn get_circom_name() -> String;
    /// Deserializes element of G1 from bytes where the element is already in montgomery form (no montgomery reduction performed)
    /// Used in default multithreaded impl of g1_vec_from_reader, because `Read` cannot be shared across threads
    fn g1_from_bytes(bytes: &[u8]) -> IoResult<Self::G1Affine>;
    /// Deserializes element of G2 from bytes where the element is already in montgomery form (no montgomery reduction performed)
    /// Used in default multithreaded impl of g2_vec_from_reader, because `Read` cannot be shared across threads
    fn g2_from_bytes(bytes: &[u8]) -> IoResult<Self::G2Affine>;
    /// Deserializes element of G1 from reader where the element is already in montgomery form (no montgomery reduction performed)
    fn g1_from_reader(reader: impl Read) -> IoResult<Self::G1Affine>;
    /// Deserializes element of G2 from reader where the element is already in montgomery form (no montgomery reduction performed)
    fn g2_from_reader(reader: impl Read) -> IoResult<Self::G2Affine>;
    /// Deserializes vec of G1 from reader where the elements are already in montgomery form (no montgomery reduction performed)
    /// The default implementation runs multithreaded using rayon
    fn g1_vec_from_reader(mut reader: impl Read, num: usize) -> IoResult<Vec<Self::G1Affine>> {
        let mut buf = vec![0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED * num];
        reader.read_exact(&mut buf)?;
        buf.par_chunks_exact(Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g1_from_bytes(chunk))
            .collect::<Result<Vec<_>, SerializationError>>()
    }
    /// Deserializes vec of G2 from reader where the elements are already in montgomery form (no montgomery reduction performed)
    /// The default implementation runs multithreaded using rayon
    fn g2_vec_from_reader(mut reader: impl Read, num: usize) -> IoResult<Vec<Self::G2Affine>> {
        let mut buf = vec![0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED * num];
        reader.read_exact(&mut buf)?;
        buf.par_chunks_exact(Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g2_from_bytes(chunk))
            .collect::<Result<Vec<_>, SerializationError>>()
    }
    /// Deserializes element of G1 from strings representing projective coordinates
    fn g1_from_strings_projective(x: &str, y: &str, z: &str) -> IoResult<Self::G1Affine>;
    /// Deserializes element of G2 from strings representing projective coordinates
    fn g2_from_strings_projective(
        x0: &str,
        x1: &str,
        y0: &str,
        y1: &str,
        z0: &str,
        z1: &str,
    ) -> IoResult<Self::G2Affine>;
    /// Deserializes element of G1 using deserializer
    fn deserialize_g1_element<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(G1Visitor::<Self>::new())
    }
    /// Deserializes element of G2 using deserializer
    fn deserialize_g2_element<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(G2Visitor::<Self>::new())
    }
    /// Deserializes element of Gt using deserializer
    fn deserialize_gt_element<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
    where
        D: de::Deserializer<'de>;
    /// Deserializes (single) element of Scalarfield using deserializer
    fn deserialize_fr_element<'de, D>(deserializer: D) -> Result<Self::ScalarField, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(FrVisitor::<Self>::new())
    }
    /// Serializes element of G1 using serializer
    fn serialize_g1<S: Serializer>(p: &Self::G1Affine, ser: S) -> Result<S::Ok, S::Error> {
        let strings = Self::g1_to_strings_projective(p);
        let mut seq = ser.serialize_seq(Some(strings.len())).unwrap();
        for ele in strings {
            seq.serialize_element(&ele)?;
        }
        seq.end()
    }
    /// Serializes element of G1 into a vec of strings
    fn g1_to_strings_projective(p: &Self::G1Affine) -> Vec<String>;
    /// Serializes element of G2 using serializer
    fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error>;
    /// Serializes element of Gt using serializer
    fn serialize_gt<S: Serializer>(p: &Self::TargetField, ser: S) -> Result<S::Ok, S::Error>;
    /// Serializes (single) element of Scalarfield using serializer
    fn serialize_fr<S: Serializer>(p: &Self::ScalarField, ser: S) -> Result<S::Ok, S::Error>;
}

/// Bridge trait to deserialize field elements contained in circom files into [`ark_ff::PrimeField`] representation
pub trait CircomArkworksPrimeFieldBridge: PrimeField {
    /// Size of serialized field element in bytes
    const SERIALIZED_BYTE_SIZE: usize;
    /// Deserializes field elements and performs montgomery reduction
    fn from_reader(reader: impl Read) -> IoResult<Self>;
    /// deserializes a big int that is already in montgomery
    /// form and creates a field element from that big int. DOES NOT perform montgomery reduction
    fn montgomery_bigint_from_reader(reader: impl Read) -> IoResult<Self>;
    /// deserializes field elements that are multiplied by R^2 already (elements in Groth16 zkey are of this form)
    fn from_reader_for_groth16_zkey(reader: impl Read) -> IoResult<Self>;
}

impl_bn256!();

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_core::protocols::rep3::{id::PartyID, network::Rep3Network};
use std::sync::mpsc::{self, Receiver, Sender};

#[derive(Debug)]
pub enum Msg {
    Data(Bytes),
    Recv(Receiver<Msg>),
}

impl Msg {
    fn into_recv(self) -> Option<Receiver<Msg>> {
        if let Msg::Recv(x) = self {
            Some(x)
        } else {
            None
        }
    }

    fn into_data(self) -> Option<Bytes> {
        if let Msg::Data(x) = self {
            Some(x)
        } else {
            None
        }
    }
}

pub struct Rep3TestNetwork {
    p1_p2_sender: Sender<Msg>,
    p1_p3_sender: Sender<Msg>,
    p2_p3_sender: Sender<Msg>,
    p2_p1_sender: Sender<Msg>,
    p3_p1_sender: Sender<Msg>,
    p3_p2_sender: Sender<Msg>,
    p1_p2_receiver: Receiver<Msg>,
    p1_p3_receiver: Receiver<Msg>,
    p2_p3_receiver: Receiver<Msg>,
    p2_p1_receiver: Receiver<Msg>,
    p3_p1_receiver: Receiver<Msg>,
    p3_p2_receiver: Receiver<Msg>,
}

impl Default for Rep3TestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Rep3TestNetwork {
    pub fn new() -> Self {
        // AT Most 1 message is buffered before they are read so this should be fine
        let p1_p2 = mpsc::channel();
        let p1_p3 = mpsc::channel();
        let p2_p3 = mpsc::channel();
        let p2_p1 = mpsc::channel();
        let p3_p1 = mpsc::channel();
        let p3_p2 = mpsc::channel();

        Self {
            p1_p2_sender: p1_p2.0,
            p1_p3_sender: p1_p3.0,
            p2_p1_sender: p2_p1.0,
            p2_p3_sender: p2_p3.0,
            p3_p1_sender: p3_p1.0,
            p3_p2_sender: p3_p2.0,
            p1_p2_receiver: p1_p2.1,
            p1_p3_receiver: p1_p3.1,
            p2_p1_receiver: p2_p1.1,
            p2_p3_receiver: p2_p3.1,
            p3_p1_receiver: p3_p1.1,
            p3_p2_receiver: p3_p2.1,
        }
    }

    pub fn get_party_networks(self) -> [PartyTestNetwork; 3] {
        let party1 = PartyTestNetwork {
            id: PartyID::ID0,
            send_prev: self.p1_p3_sender,
            recv_prev: self.p3_p1_receiver,
            send_next: self.p1_p2_sender,
            recv_next: self.p2_p1_receiver,
            _stats: [0; 4],
        };

        let party2 = PartyTestNetwork {
            id: PartyID::ID1,
            send_prev: self.p2_p1_sender,
            recv_prev: self.p1_p2_receiver,
            send_next: self.p2_p3_sender,
            recv_next: self.p3_p2_receiver,
            _stats: [0; 4],
        };

        let party3 = PartyTestNetwork {
            id: PartyID::ID2,
            send_prev: self.p3_p2_sender,
            recv_prev: self.p2_p3_receiver,
            send_next: self.p3_p1_sender,
            recv_next: self.p1_p3_receiver,
            _stats: [0; 4],
        };

        [party1, party2, party3]
    }
}

#[derive(Debug)]
pub struct PartyTestNetwork {
    pub id: PartyID,
    pub send_prev: Sender<Msg>,
    pub send_next: Sender<Msg>,
    pub recv_prev: Receiver<Msg>,
    pub recv_next: Receiver<Msg>,
    pub _stats: [usize; 4], // [sent_prev, sent_next, recv_prev, recv_next]
}

impl Rep3Network for PartyTestNetwork {
    fn get_id(&self) -> PartyID {
        self.id
    }

    fn reshare_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<Vec<F>> {
        self.send_next_many(data)?;
        self.recv_prev_many()
    }

    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: F,
    ) -> std::io::Result<(F, F)> {
        let data = [data];
        self.send_many(self.id.next_id(), &data)?;
        self.send_many(self.id.prev_id(), &data)?;
        let mut prev = self.recv_many(self.id.prev_id())?;
        let mut next = self.recv_many(self.id.next_id())?;
        if next.len() != 1 || prev.len() != 1 {
            panic!("got more than one from next or prev");
        }
        Ok((prev.pop().unwrap(), next.pop().unwrap()))
    }

    fn broadcast_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<(Vec<F>, Vec<F>)> {
        self.send_many(self.id.next_id(), data)?;
        self.send_many(self.id.prev_id(), data)?;
        let prev = self.recv_many(self.id.prev_id())?;
        let next = self.recv_many(self.id.next_id())?;
        Ok((prev, next))
    }

    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut to_send = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut to_send).unwrap();
        if self.id.next_id() == target {
            self.send_next
                .send(Msg::Data(Bytes::from(to_send)))
                .expect("can send to next")
        } else if self.id.prev_id() == target {
            self.send_prev
                .send(Msg::Data(Bytes::from(to_send)))
                .expect("can send to next");
        } else {
            panic!("You want to send to yourself?")
        }
        Ok(())
    }

    fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>> {
        if self.id.next_id() == from {
            let data = Vec::from(self.recv_next.recv().unwrap().into_data().unwrap());
            Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else if self.id.prev_id() == from {
            let data = Vec::from(self.recv_prev.recv().unwrap().into_data().unwrap());
            Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else {
            panic!("You want to read from yourself?")
        }
    }

    fn fork(&mut self) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        let ch_prev = mpsc::channel();
        let ch_next = mpsc::channel();

        self.send_next.send(Msg::Recv(ch_next.1)).unwrap();
        self.send_prev.send(Msg::Recv(ch_prev.1)).unwrap();

        let recv_prev = self.recv_prev.recv().unwrap().into_recv().unwrap();
        let recv_next = self.recv_next.recv().unwrap().into_recv().unwrap();

        let id = self.id;

        Ok(Self {
            id,
            send_prev: ch_prev.0,
            send_next: ch_next.0,
            recv_prev,
            recv_next,
            _stats: [0; 4],
        })
    }
}
