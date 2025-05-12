use libgrease::crypto::keys::Curve25519PublicKey;
use libgrease::crypto::traits::PublicKey;

pub fn print_random_keypair() -> Result<(), anyhow::Error> {
    let (secret, public) = Curve25519PublicKey::keypair(&mut rand::rng());
    println!("Private Key: {}", secret.as_hex());
    println!("Public Key: {}", public.as_hex());
    Ok(())
}
