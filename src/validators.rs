use anyhow::{anyhow, Result};
use url::Url;
use validator::ValidationError;

pub fn parse_validate_unf_url(unf_url: &str) -> Result<Url> {
    let url: Url = Url::parse(unf_url)?;
    match url.path_segments() {
        Some(x) => {
            if x.last().unwrap() != "update-notification-file.jose" {
                return Err(anyhow!(
                    "Filename of Update Notification File must be update-notification-file.jose"
                ));
            }
        }
        None => return Err(anyhow!("Unable to find filename in URL")),
    };
    Ok(url)
}

pub fn validate_pem(input: &str) -> Result<String> {
    let pem = pem::parse(input)?;
    if pem.tag() == "PUBLIC KEY" {
        return Ok(input.to_string());
    } else {
        return Err(anyhow::anyhow!("Invalid PEM format"));
    }
}

pub fn validate_signing_key(signing_key: &str) -> Result<(), ValidationError> {
    if validate_pem(signing_key).is_err() {
        return Err(ValidationError::new("Invalid public key"));
    }
    Ok(())
}

pub fn is_contiguous_and_ordered(numbers: &[u32]) -> bool {
    if numbers.is_empty() {
        return true;
    }
    numbers.windows(2).all(|window| window[1] == window[0] + 1)
}

pub fn check_consistency<T: PartialEq + std::fmt::Display>(
    in_subfile: &T,
    in_unf: &T,
    field_human_name: &str,
    file_human_name: &str,
) -> Result<()> {
    if in_subfile != in_unf {
        return Err(anyhow!(
            "{} does not match: {} File has '{}', expecting '{}'",
            field_human_name,
            file_human_name,
            in_subfile,
            in_unf,
        ));
    }
    Ok(())
}
