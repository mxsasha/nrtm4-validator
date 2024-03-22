mod types;

use clap::Parser;
use reqwest::Error;
use std::process;
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
async fn main() -> Result<(), Error> {
    let args = Cli::parse();
    if !args
        .update_notification_url
        .to_string()
        // TODO: path_segments
        .ends_with("/update-notification-file.json")
    {
        println!(
            "Error: filename of Update Notification File must be update-notification-file.json"
        );
        process::exit(1);
    }

    get_request(args.update_notification_url).await?;
    Ok(())
}

async fn get_request(url: Url) -> Result<(), Error> {
    let response = reqwest::get(url).await?;
    println!("Status: {}", response.status());

    let body = response.text().await?;
    println!("Body size:\n{}", body.len());

    let update_notification_file: types::NRTM4UpdateNotificationFile =
        serde_json::from_str(&body).unwrap();
    let x = update_notification_file.validate();
    println!("{:#?}", x);

    Ok(())
}
