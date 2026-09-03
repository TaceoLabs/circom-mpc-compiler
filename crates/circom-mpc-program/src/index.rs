//! Typed `u32` indices for the wire format's five distinct index roles - a physical bank slot, a
//! round table index, a gadget batch table index, a flat circuit input index, and a gadget site's
//! logical result ordinal. Kept as thin newtypes over `u32` (the wire width) rather than `usize`
//! (the natural indexing width) so a slot can never be mistaken for a round or batch index at a
//! type level, and so a caller building a `Program` by hand gets a checked error instead of a
//! silent truncation on a pathologically large circuit.

macro_rules! index_type {
    ($name:ident, $what:literal) => {
        #[doc = concat!("A ", $what, ".")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            #[doc = concat!("Builds a ", $what, " from its raw wire value.")]
            #[must_use]
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            /// The raw wire value.
            #[must_use]
            pub const fn get(self) -> u32 {
                self.0
            }

            /// The value as a `usize`, for indexing.
            #[must_use]
            pub const fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl TryFrom<usize> for $name {
            type Error = eyre::Report;

            fn try_from(raw: usize) -> Result<Self, Self::Error> {
                u32::try_from(raw).map(Self).map_err(|_| {
                    eyre::eyre!(concat!($what, " {raw} does not fit into u32"), raw = raw)
                })
            }
        }
    };
}

index_type!(Slot, "bank-relative physical slot index");
index_type!(RoundIdx, "index into Program::rounds");
index_type!(BatchIdx, "index into Program::gadget_batches");
index_type!(InputIdx, "flat circuit input index");
index_type!(ResultSlot, "gadget site's logical result ordinal");
