//! Canonical serialization traits for grease wire types.
//!
//! These mirror the `write`/`serialize` shape that `modular_frost::sign::Writable` provides, but live in-tree so that
//! grease's own wire formats do not depend on the FROST crate. FROST's own types (preprocesses, signature shares)
//! continue to use the upstream trait; only grease types implement these.

use crate::error::ReadError;
use std::io::{self, Read, Write};

/// A type that can be written to a byte sink in its canonical wire form.
pub trait Writable {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;

    fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.write(&mut buf).expect("writing to a Vec cannot fail");
        buf
    }
}

impl<T: Writable> Writable for Vec<T> {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.iter().try_for_each(|item| item.write(writer))
    }
}

/// The inverse of [`Writable`]: a type that can be reconstructed from its canonical wire form.
pub trait Readable: Sized {
    fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError>;
}
