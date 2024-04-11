mod jsonseq;
mod nrtm4_types;
mod retrieval;

use crate::nrtm4_types::NRTM4DeltaEntry;
use crate::nrtm4_types::NRTM4DeltaFile;
use crate::nrtm4_types::NRTM4DeltaHeader;
use crate::nrtm4_types::NRTM4SnapshotEntry;
use crate::nrtm4_types::NRTM4SnapshotFile;
use crate::nrtm4_types::NRTM4SnapshotHeader;
use crate::nrtm4_types::NRTM4UpdateNotificationFile;
use crate::retrieval::{retrieve_bytes, retrieve_jsonseq};
use anyhow::anyhow;
use anyhow::Result;
use base64::prelude::*;
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha256::digest;
use url::Url;
use validator::Validate;

/// Validate an NRTMv4 server
#[derive(clap::Parser)]
struct Cli {
    /// URL to the update notification file
    update_notification_url: Url,
    /// Name of the IRR source
    source: String,
    /// Public key in base64
    #[arg(value_parser = parse_public_key)]
    public_key: VerifyingKey,
}

fn parse_public_key(public_key_str: &str) -> Result<VerifyingKey> {
    let key_bytes: [u8; 32] = BASE64_STANDARD
        .decode(public_key_str)?
        .as_slice()
        .try_into()?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    match args.update_notification_url.path_segments() {
        Some(x) => {
            if x.last().unwrap() != "update-notification-file.json" {
                return Err(anyhow!(
                    "Filename of Update Notification File must be update-notification-file.json"
                ));
            }
        }
        None => return Err(anyhow!("Unable to find filename in URL")),
    };

    let unf = retrieve_nrtm4_unf(args.update_notification_url, args.public_key).await?;
    if unf.source != args.source {
        return Err(anyhow!(
            "Source does not match: Update Notification File has '{}', expecting '{}'",
            unf.source,
            args.source
        ));
    }
    let snapshot =
        retrieve_nrtm4_snapshot(unf.snapshot.url.clone(), Some(&unf.snapshot.hash)).await?;
    println!("Snapshot header: {:?}", snapshot.header);
    snapshot.validate_unf_consistency(&unf)?;

    for delta_reference in unf.deltas.iter() {
        let delta =
            retrieve_nrtm4_delta(delta_reference.url.clone(), Some(&delta_reference.hash)).await?;
        println!("Delta header: {:?}", delta.header);
        delta.validate_unf_consistency(&unf, delta_reference.version)?;
    }
    Ok(())
}

async fn retrieve_nrtm4_unf(
    url: Url,
    public_key: VerifyingKey,
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
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(signature_response_str)?
        .as_slice()
        .try_into()?;
    public_key.verify(&response_bytes, &Signature::from_bytes(&signature_bytes))?;
    let nrtm4_struct: NRTM4UpdateNotificationFile =
        serde_json::from_str(&String::from_utf8_lossy(&response_bytes))?;
    nrtm4_struct.validate()?;
    Ok(nrtm4_struct)
}

async fn retrieve_nrtm4_delta(url: Url, expected_hash: Option<&String>) -> Result<NRTM4DeltaFile> {
    let (header_content, jsonseq_iter) = retrieve_jsonseq(url, expected_hash).await?;
    let header: NRTM4DeltaHeader = serde_json::from_str(&header_content)?;
    header.validate()?;
    let entries: Result<Vec<NRTM4DeltaEntry>> = jsonseq_iter
        .map(|record| {
            let record_content: String = record?;
            Ok(serde_json::from_str(&record_content)?)
        })
        .collect();
    Ok(NRTM4DeltaFile {
        header,
        entries: entries?,
    })
}

// async fn retrieve_nrtm4_snapshot(
//     url: Url,
//     expected_hash: Option<&String>,
// ) -> Result<NRTM4SnapshotFile> {
//     let (header_content, jsonseq_iter) = retrieve_jsonseq(url, expected_hash).await?;
//     let header: NRTM4SnapshotHeader = serde_json::from_str(&header_content)?;
//     header.validate()?;
//     let entries: Result<Vec<NRTM4SnapshotEntry>> = jsonseq_iter
//         .map(|record| {
//             let record_content: String = record?;
//             Ok(serde_json::from_str(&record_content)?)
//         })
//         .collect();
//     Ok(NRTM4SnapshotFile {
//         header,
//         entries: entries?,
//     })
// }

async fn retrieve_nrtm4_snapshot(
    url: Url,
    expected_hash: Option<&String>,
) -> Result<NRTM4SnapshotFile> {
    let (header_content, jsonseq_iter) = retrieve_jsonseq(url, expected_hash).await?;
    let header: NRTM4SnapshotHeader = serde_json::from_str(&header_content)?;
    header.validate()?;
    let entries: Result<Vec<NRTM4SnapshotEntry>> = jsonseq_iter
        .map(|record| {
            let record_content: String = record?;
            Ok(serde_json::from_str(&record_content)?)
        })
        .collect();
    Ok(NRTM4SnapshotFile {
        header,
        entries: entries?,
    })
}
