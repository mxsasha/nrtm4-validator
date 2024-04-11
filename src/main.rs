mod crypto;
mod jsonseq;
mod nrtm4_types;
mod retrieval;

use crate::crypto::{check_signature, parse_public_key};
use crate::nrtm4_types::{
    NRTM4DeltaFile, NRTM4File, NRTM4SnapshotFile, NRTM4UpdateNotificationFile,
};
use crate::retrieval::{retrieve_bytes, retrieve_jsonseq};
use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use sha256::digest;
use url::Url;
use validator::Validate;

/// Validate an NRTMv4 server
#[derive(clap::Parser)]
struct Cli {
    /// URL to the update notification file
    #[arg(value_parser = parse_update_notification_url)]
    update_notification_url: Url,
    /// Name of the IRR source
    source: String,
    /// Public key in base64
    #[arg(value_parser = parse_public_key)]
    public_key: VerifyingKey,
}

fn parse_update_notification_url(update_notification_url: &str) -> Result<Url> {
    let url: Url = Url::parse(update_notification_url)?;
    match url.path_segments() {
        Some(x) => {
            if x.last().unwrap() != "update-notification-file.json" {
                return Err(anyhow!(
                    "Filename of Update Notification File must be update-notification-file.json"
                ));
            }
        }
        None => return Err(anyhow!("Unable to find filename in URL")),
    };
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    load_nrtm4(args.update_notification_url, &args.public_key, &args.source).await?;
    Ok(())
}

async fn load_nrtm4(
    update_notification_url: Url,
    public_key: &VerifyingKey,
    source: &str,
) -> Result<NRTM4UpdateNotificationFile> {
    let unf = retrieve_nrtm4_unf(update_notification_url, public_key).await?;
    if unf.source != source {
        return Err(anyhow!(
            "Source does not match: Update Notification File has '{}', expecting '{}'",
            unf.source,
            source
        ));
    }
    let (header_content, jsonseq_iter) =
        retrieve_jsonseq(unf.snapshot.url.clone(), Some(&unf.snapshot.hash)).await?;
    let snapshot = NRTM4SnapshotFile::from_header_and_records(header_content, jsonseq_iter)?;
    snapshot.validate_unf_consistency(&unf)?;

    for delta_reference in unf.deltas.iter() {
        let (header_content, jsonseq_iter) =
            retrieve_jsonseq(delta_reference.url.clone(), Some(&delta_reference.hash)).await?;
        let delta = NRTM4DeltaFile::from_header_and_records(header_content, jsonseq_iter)?;
        delta.validate_unf_consistency(&unf, delta_reference.version)?;
    }
    Ok(unf)
}

async fn retrieve_nrtm4_unf(
    url: Url,
    public_key: &VerifyingKey,
) -> Result<NRTM4UpdateNotificationFile> {
    println!(
        "Retrieving and validating Update Notification File from {}",
        url
    );
    let response_bytes = retrieve_bytes(url.clone(), None).await?;
    let mut signature_url = url.to_string().replace(
        "update-notification-file.json",
        &format!(
            "update-notification-file-signature-{}.sig",
            digest(&response_bytes).as_str()
        ),
    );
    if url.to_string().contains("nrtm.db.ripe.net") {
        signature_url = url.to_string();
        signature_url.push_str(".sig");
    }
    let signature_response_str = retrieve_bytes(Url::parse(&signature_url)?, None).await?;
    check_signature(public_key, &response_bytes, &signature_response_str)?;
    let nrtm4_struct: NRTM4UpdateNotificationFile =
        serde_json::from_str(&String::from_utf8_lossy(&response_bytes))?;
    nrtm4_struct.validate()?;
    Ok(nrtm4_struct)
}
