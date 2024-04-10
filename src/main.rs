mod jsonseq;
mod types;

use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use sha256::digest;
use types::NRTM4DeltaEntry;
use types::NRTM4DeltaFile;
use types::NRTM4DeltaHeader;
use types::NRTM4SnapshotEntry;
use types::NRTM4SnapshotFile;
use types::NRTM4SnapshotHeader;
use types::NRTM4UpdateNotificationFile;
use url::Url;
use validator::Validate;

use jsonseq::{gunzip, JSONSequenceIterator};

/// Validate an NRTMv4 server
#[derive(clap::Parser)]
struct Cli {
    /// URL to the update notification file
    update_notification_url: Url,
    /// Name of the IRR source
    source: String,
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

    let unf = retrieve_nrtm4_unf(args.update_notification_url, None).await?;
    if unf.source != args.source {
        return Err(anyhow!(
            "Source does not match: Update Notification File has '{}', expecting '{}'",
            unf.source,
            args.source
        ));
    }
    for delta_reference in unf.deltas {
        let delta = retrieve_nrtm4_delta(delta_reference.url, Some(delta_reference.hash)).await?;
        println!("Delta header: {:?}", delta.header);
        check_consistency(&delta.header.source, &unf.source, "soure", "Delta")?;
        check_consistency(
            &delta.header.session_id,
            &unf.session_id,
            "session_id",
            "Delta",
        )?;
        check_consistency(
            &delta.header.version,
            &delta_reference.version,
            "version",
            "Delta",
        )?;
    }
    let snapshot = retrieve_nrtm4_snapshot(unf.snapshot.url, Some(unf.snapshot.hash)).await?;
    println!("Snapshot header: {:?}", snapshot.header);
    check_consistency(&snapshot.header.source, &unf.source, "soure", "Snapshot")?;
    check_consistency(
        &snapshot.header.session_id,
        &unf.session_id,
        "session_id",
        "Snapshot",
    )?;
    check_consistency(
        &snapshot.header.version,
        &unf.snapshot.version,
        "version",
        "Snapshot",
    )?;
    Ok(())
}

fn check_consistency<T: PartialEq + std::fmt::Display>(
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
// async fn retrieve_and_validate_nrtm4_file<T: for<'a> Deserialize<'a> + Validate>(
async fn retrieve_nrtm4_unf(
    url: Url,
    expected_hash: Option<String>,
) -> Result<NRTM4UpdateNotificationFile> {
    println!(
        "Retrieving and validating Update Notification File from {}",
        url
    );
    let response_bytes = retrieve_bytes(url.clone(), expected_hash).await?;
    let nrtm4_struct: NRTM4UpdateNotificationFile =
        serde_json::from_str(&String::from_utf8_lossy(&response_bytes))?;
    nrtm4_struct.validate()?;
    Ok(nrtm4_struct)
}

async fn retrieve_nrtm4_delta(url: Url, expected_hash: Option<String>) -> Result<NRTM4DeltaFile> {
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

async fn retrieve_nrtm4_snapshot(
    url: Url,
    expected_hash: Option<String>,
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

async fn retrieve_jsonseq(
    url: Url,
    expected_hash: Option<String>,
) -> Result<(String, JSONSequenceIterator)> {
    println!("Retrieving and validating {}", url);
    let response_bytes = retrieve_bytes(url.clone(), expected_hash).await?;
    let mut iter = JSONSequenceIterator::new(gunzip(response_bytes)?);
    let header_content: String = iter
        .next()
        .unwrap_or_else(|| Err(anyhow!("No header found")))?;
    Ok((header_content, iter))
}

async fn retrieve_bytes(url: Url, expected_hash: Option<String>) -> Result<Vec<u8>> {
    let response = reqwest::get(url.clone()).await?;
    let body = response.bytes().await?;
    let response_bytes = body.into_iter().collect();
    if let Some(hash) = expected_hash {
        if digest(&response_bytes) != hash {
            return Err(anyhow!("Invalid hash for URL {}", url));
        }
    }
    Ok(response_bytes)
}
