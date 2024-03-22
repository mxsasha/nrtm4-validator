use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4SnapshotHeader {
    #[validate(range(min = 4, max = 4))]
    nrtm_version: u8,
    source: String,
    session_id: Uuid,
    version: u32,
    #[serde(rename = "type")]
    header_type: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4DeltaHeader {
    #[validate(range(min = 4, max = 4))]
    nrtm_version: u8,
    source: String,
    session_id: Uuid,
    version: u32,
    #[serde(rename = "type")]
    header_type: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[validate(nested)]
pub struct NRTM4FileReference {
    version: u32,
    #[validate(custom(function = "validate_url"))]
    url: Url,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4UpdateNotificationFile {
    #[validate(range(min = 4, max = 4))]
    nrtm_version: u8,
    source: String,
    session_id: Uuid,
    version: u32,
    timestamp: DateTime<Utc>,
    #[serde(rename = "type")]
    file_type: String,
    #[validate(nested)]
    snapshot: NRTM4FileReference,
    // TODO: validate
    deltas: Vec<NRTM4FileReference>,
    next_signing_key: Option<String>,
}

fn validate_url(url: &Url) -> Result<(), ValidationError> {
    if url.scheme() != "https" {
        return Err(ValidationError::new("Invalid URL scheme"));
    }
    Ok(())
}
