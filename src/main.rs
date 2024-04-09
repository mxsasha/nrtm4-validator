mod types;

use crate::types::NRTM4UpdateNotificationFile;
use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use sha256::digest;
use types::NRTM4SnapshotHeader;
use url::Url;
use validator::Validate;

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

    let unf: NRTM4UpdateNotificationFile = retrieve_and_validate_nrtm4_file(
        args.update_notification_url,
        Some(String::from(
            "7df5d97af14faae118ef03668bcca5f9e9bad2421e619674a3d22f910b751876",
        )),
    )
    .await?;
    if unf.source != args.source {
        return Err(anyhow!(
            "Source does not match: Update Notification File has '{}', expecting '{}'",
            unf.source,
            args.source
        ));
    }
    let snapshot: NRTM4SnapshotHeader =
        retrieve_and_validate_nrtm4_file(unf.snapshot.url, Some(unf.snapshot.hash)).await?;
    Ok(())
}

async fn retrieve_and_validate_nrtm4_file<T: for<'a> Deserialize<'a> + Validate>(
    url: Url,
    expected_hash: Option<String>,
) -> Result<T> {
    let response = reqwest::get(url.clone()).await?;
    let body = response.text().await?;
    match expected_hash {
        Some(hash) => {
            if digest(&body) != hash {
                return Err(anyhow!(
                    "Invalid hash for URL {}: expected {} but found {} for body len {}",
                    url,
                    hash,
                    digest(&body),
                    body.len()
                ));
            }
        }
        None => (),
    };
    let nrtm4_struct: T = serde_json::from_str(&body)?;
    nrtm4_struct.validate()?;
    Ok(nrtm4_struct)
}
