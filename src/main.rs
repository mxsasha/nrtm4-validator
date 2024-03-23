mod jsonseq;
mod nrtm4;
mod nrtm4_types;
mod retrieval;
mod validators;

use anyhow::Result;
use clap::Parser;
use nrtm4::retrieve_validate_nrtmv4;
use url::Url;
use validators::{parse_validate_unf_url, validate_pem};

/// Validate an NRTMv4 server
#[derive(clap::Parser)]
struct Cli {
    /// URL to the update notification file
    #[arg(value_parser = parse_validate_unf_url)]
    update_notification_url: Url,
    /// Name of the IRR source
    source: String,
    /// Public key in PEM
    #[arg(value_parser = validate_pem, allow_hyphen_values = true)]
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    retrieve_validate_nrtmv4(args.update_notification_url, &args.source, &args.public_key).await?;
    Ok(())
}
