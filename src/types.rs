use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4SnapshotHeader {
    #[validate(range(min = 4, max = 4))]
    pub nrtm_version: u8,
    pub source: String,
    pub session_id: Uuid,
    pub version: u32,
    #[serde(rename = "type")]
    pub header_type: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4DeltaHeader {
    #[validate(range(min = 4, max = 4))]
    pub nrtm_version: u8,
    pub source: String,
    pub session_id: Uuid,
    pub version: u32,
    #[serde(rename = "type")]
    pub header_type: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4FileReference {
    pub version: u32,
    #[validate(custom(function = "validate_url"))]
    pub url: Url,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4UpdateNotificationFile {
    #[validate(range(min = 4, max = 4))]
    pub nrtm_version: u8,
    pub source: String,
    pub session_id: Uuid,
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "type")]
    pub file_type: String,
    #[validate(nested)]
    pub snapshot: NRTM4FileReference,
    #[validate(nested)]
    pub deltas: Vec<NRTM4FileReference>,
    pub next_signing_key: Option<String>,
}

fn validate_url(url: &Url) -> Result<(), ValidationError> {
    if url.scheme() != "https" {
        return Err(ValidationError::new("Invalid URL scheme"));
    }
    Ok(())
}
