use anyhow::Result;
use base64::prelude::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn parse_public_key(public_key_str: &str) -> Result<VerifyingKey> {
    let key_bytes: [u8; 32] = BASE64_STANDARD
        .decode(public_key_str)?
        .as_slice()
        .try_into()?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

pub fn check_signature(
    public_key: &VerifyingKey,
    content: &[u8],
    signature_base64: &[u8],
) -> Result<()> {
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(signature_base64)?
        .as_slice()
        .try_into()?;
    public_key.verify(content, &Signature::from_bytes(&signature_bytes))?;
    Ok(())
}
