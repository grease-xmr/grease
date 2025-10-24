use crate::error::ReadError;
use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use paste::paste;
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

macro_rules! schnorr_def {
    ($name:ident, $s:ident) => {
        impl<C: Ciphersuite> $name<C> {
            #[allow(non_snake_case)]
            fn challenge<B: AsRef<[u8]>>(R: &C::G, pubkey: &C::G, msg: B) -> C::F {
                use ciphersuite::group::GroupEncoding;
                let bytes = [
                    b"R",
                    R.to_bytes().as_ref(),
                    b"P",
                    pubkey.to_bytes().as_ref(),
                    b"MSG",
                    (msg.as_ref().len() as u64).to_le_bytes().as_ref(),
                    msg.as_ref(),
                ]
                .concat();
                C::hash_to_F(b"AdaptedSignature-challenge", &bytes)
            }
        }

        impl<C: Ciphersuite> Zeroize for $name<C> {
            fn zeroize(&mut self) {
                self.$s.zeroize();
            }
        }

        impl<C: Ciphersuite> ZeroizeOnDrop for $name<C> {}

        impl<C: Ciphersuite> Drop for $name<C> {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
}

#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct SchnorrSignature<C: Ciphersuite> {
    R: C::G,
    s: C::F,
}
schnorr_def!(SchnorrSignature, s);

impl<C: Ciphersuite> SchnorrSignature<C> {
    /// Create a new adapter signature.
    ///
    /// The returned signature signs a challenge bound to $R$ and $P = k\cdot G$, such that if we knew $q, Q = q\cdot G$
    /// we could easily calculate a valid signature $(s,R)$ for the same challenge.
    #[allow(non_snake_case)]
    pub fn sign<B: AsRef<[u8]>, R: RngCore + CryptoRng>(secret: &C::F, msg: B, rng: &mut R) -> Self {
        let mut nonce = C::F::random(rng.as_rngcore());
        while nonce == C::F::ZERO {
            nonce = C::F::random(rng.as_rngcore());
        }
        let R = C::generator() * &nonce;
        let pubkey = C::generator() * secret;
        let e = Self::challenge(&R, &pubkey, msg);
        let s = nonce + (e * secret);
        nonce.zeroize();
        Self { R, s }
    }

    /// Verify the adapted signature against the provided public key and message.
    #[allow(non_snake_case)]
    pub fn verify<B: AsRef<[u8]>>(&self, public_key: &C::G, msg: B) -> bool {
        let e = Self::challenge(&self.R, public_key, msg);
        let sG = C::generator() * &self.s;
        let rhs = self.R + (*public_key * e);
        sG == rhs
    }

    pub fn s(&self) -> &C::F {
        &self.s
    }
}

#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct AdaptedSignature<C: Ciphersuite> {
    Q: C::G,
    R: C::G,
    s_adapted: C::F,
}
schnorr_def!(AdaptedSignature, s_adapted);

impl<C: Ciphersuite> AdaptedSignature<C> {
    /// Create a new adapter signature.
    ///
    /// The returned signature signs a challenge bound to $R$ and $P = k\cdot G$, such that if we knew $q, Q = q\cdot G$
    /// we could easily calculate a valid signature $(s,R)$ for the same challenge.
    #[allow(non_snake_case)]
    pub fn sign<B: AsRef<[u8]>, R: RngCore + CryptoRng>(secret: &C::F, payload: &C::F, msg: B, rng: &mut R) -> Self {
        let mut nonce = C::F::random(rng.as_rngcore());
        while nonce == C::F::ZERO {
            nonce = C::F::random(rng.as_rngcore());
        }
        let pubkey = C::generator() * secret;
        let R = C::generator() * &nonce;
        let Q = C::generator() * payload;
        let e = Self::challenge(&R, &pubkey, msg);
        let s_adapted = nonce + payload + (e * secret);
        nonce.zeroize();
        AdaptedSignature { Q, R, s_adapted }
    }

    /// Verify the adapted signature against the provided public key and message.
    #[allow(non_snake_case)]
    pub fn verify<B: AsRef<[u8]>>(&self, public_key: &C::G, msg: B) -> bool {
        let e = Self::challenge(&self.R, public_key, msg);
        let sG = C::generator() * &self.s_adapted;
        let rhs = self.R + &self.Q + (*public_key * e);
        sG == rhs
    }

    /// Adapt the signature using the provided payload, and verifying that the payload is correct.
    pub fn adapt<B: AsRef<[u8]>>(&self, payload: &C::F, pubkey: &C::G, msg: B) -> Result<SchnorrSignature<C>, ()> {
        let sig = self.adapt_no_verify(payload);
        match sig.verify(pubkey, msg) {
            true => Ok(sig),
            false => Err(()),
        }
    }

    /// Adapt the signature using the provided payload, without verifying that the payload is correct.
    pub fn adapt_no_verify(&self, payload: &C::F) -> SchnorrSignature<C> {
        let s = self.s_adapted - payload;
        SchnorrSignature::<C> { R: self.R, s }
    }
}

macro_rules! schnorr_impl {
    ($name:ident ($count:expr) scalars=[$($s_field:ident),*] points=[$($p_field:ident),*]) => {
        impl<C: Ciphersuite> Serialize for $name<C> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), $count)?;
                $(
                    state.serialize_field(stringify!($p_field), &self.$p_field.to_bytes().as_ref())?;
                )*
                $(
                    state.serialize_field(stringify!($s_field), &self.$s_field.to_repr().as_ref())?;
                )*
                state.end()
            }
        }

        impl<'de, C: Ciphersuite> Deserialize<'de> for $name<C> {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                use serde::de::{Error, MapAccess, Visitor};
                use std::fmt;

                struct SigVisitor<C: Ciphersuite> {
                    marker: std::marker::PhantomData<C>,
                }

                impl<'de, C: Ciphersuite> Visitor<'de> for SigVisitor<C> {
                    type Value = $name<C>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(concat!("struct ", stringify!($name)))
                    }

                    #[allow(non_snake_case)]
                    fn visit_map<V: MapAccess<'de>>(self, mut map: V) -> Result<Self::Value, V::Error> {
                        $(
                            paste!{ let mut [<$p_field _opt>]: Option<C::G> = None; }
                        )*
                        $(
                            paste!{ let mut [<$s_field _opt>]: Zeroizing<Option<C::F>> = Zeroizing::new(None); }
                        )*

                        while let Some(key) = map.next_key::<String>()? {
                            match key.as_str() {
                                $(
                                    stringify!($p_field) => {
                                        let mut val: Zeroizing<Vec<u8>> = Zeroizing::new(map.next_value()?);
                                        let mut bytes = <C::G as GroupEncoding>::Repr::default();
                                        if val.len() != bytes.as_ref().len() {
                                            return Err(Error::custom(concat!("invalid point length for ", stringify!($p_field))));
                                        }
                                        bytes.as_mut().copy_from_slice(&val);
                                        let point = C::G::from_bytes(&bytes)
                                            .into_option()
                                            .ok_or_else(|| Error::custom(concat!("invalid point length for ", stringify!($p_field))))?;
                                        paste! { [<$p_field _opt>] = Some(point); }
                                        val.zeroize();
                                    }
                                )*

                                $(
                                    stringify!($s_field) => {
                                        let mut bytes: Vec<u8> = map.next_value()?;
                                        let mut repr = <C::F as PrimeField>::Repr::default();
                                        if bytes.len() != repr.as_ref().len() {
                                            return Err(Error::custom(concat!("invalid scalar length for ", stringify!($s_field))));
                                        }
                                        repr.as_mut().copy_from_slice(&bytes);
                                        paste!{
                                            *[<$s_field _opt>]  = C::F::from_repr(repr).into_option();
                                            if [<$s_field _opt>].is_none() {
                                                return Err(Error::custom(concat!("invalid scalar type for ", stringify!($s_field))));
                                            }
                                        }
                                        bytes.zeroize();
                                    }
                                )*
                                _ => return Err(Error::unknown_field(&key, &[
                                    $( stringify!($p_field), )*
                                    $( stringify!($s_field), )*
                                ])),
                            }
                        }

                        paste!{
                            $(
                            let $p_field = [< $p_field _opt>].ok_or_else(|| V::Error::missing_field(stringify!($p_field)))?;
                            )*
                        }
                        paste!{
                            $(
                            let $s_field = [< $s_field _opt>].ok_or_else(|| V::Error::missing_field(stringify!($s_field)))?;
                            )*
                        }
                        let sig = $name {
                            $( $p_field, )*
                            $( $s_field, )*
                        };
                        paste!{
                            $( [<$s_field _opt>].zeroize(); )*
                        }
                        Ok(sig)
                    }
                }

                deserializer.deserialize_struct(
                    stringify!($name),
                    &[
                        $( stringify!($p_field), )*
                        $( stringify!($s_field), )*
                    ],
                    SigVisitor { marker: std::marker::PhantomData },
                )
            }
        }

        impl<C: Ciphersuite> PartialEq for $name<C> {
            fn eq(&self, other: &Self) -> bool {
                use subtle::ConstantTimeEq;
                true
                $(
                  && (self.$p_field == other.$p_field)
                )*
                $(
                    && (self.$s_field.ct_eq(&other.$s_field).unwrap_u8() == 1)
                )*
            }
        }

        impl<C: Ciphersuite> Writable for $name<C> {
            fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                use crate::grease_protocol::utils::{write_group_element, write_field_element};
                $( write_field_element::<C, _>(writer, &self.$s_field)?; )*
                $( write_group_element::<C, _>(writer, &self.$p_field)?; )*
                Ok(())
            }
        }

        #[allow(non_snake_case)]
        impl<C: Ciphersuite> $name<C> {
            /// Read the signature from the provided reader.
            pub fn read<R: std::io::Read>(reader: &mut R) -> Result<Self, ReadError> {
                use crate::grease_protocol::utils::{read_group_element, read_field_element};
                $(
                    let $s_field = read_field_element::<C, _>(reader)
                    .map_err(|e| ReadError::new(
                        concat!(stringify!($name), ".", stringify!($s_field)),
                        e.to_string()
                    ))?;
                )*
                $(
                    let $p_field = read_group_element::<C, _>(reader)
                        .map_err(|e| ReadError::new(
                            concat!(stringify!($name), ".", stringify!($p_field)),
                            e.to_string()
                    ))?;
                )*
                Ok(Self {
                    $( $s_field, )*
                    $( $p_field, )*
                })
            }
        }
    }
}

schnorr_impl!(AdaptedSignature (3) scalars=[s_adapted] points=[Q, R]);
schnorr_impl!(SchnorrSignature (2) scalars=[s] points=[R]);

#[cfg(test)]
mod tests {
    use crate::adapter_signature::{AdaptedSignature, SchnorrSignature};
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use ciphersuite::{Ciphersuite, Ed25519};

    #[test]
    fn adapter_signature_ed25519() {
        let mut rng = rand_core::OsRng;
        let k = XmrScalar::random(&mut rng);
        let public_key = Ed25519::generator() * &k;
        let q = XmrScalar::random(&mut rng);

        let msg = b"test message";

        let adapted_sig = AdaptedSignature::<Ed25519>::sign(&k, &q, msg, &mut rng);
        assert!(adapted_sig.verify(&public_key, msg));
        let reconstructed = adapted_sig.adapt(&q, &public_key, msg).unwrap();
        assert!(reconstructed.verify(&public_key, msg));
    }
}
