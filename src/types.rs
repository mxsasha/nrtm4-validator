use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Debug)]
pub struct NRTM4SnapshotFile {
    pub header: NRTM4SnapshotHeader,
    pub entries: Vec<NRTM4SnapshotEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NRTM4SnapshotHeaderType {
    Snapshot,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4SnapshotHeader {
    #[validate(range(min = 4, max = 4))]
    pub nrtm_version: u8,
    pub source: String,
    pub session_id: Uuid,
    pub version: u32,
    #[serde(rename = "type")]
    pub header_type: NRTM4SnapshotHeaderType,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NRTM4SnapshotEntry {
    pub object: String,
}

#[derive(Debug)]
pub struct NRTM4DeltaFile {
    pub header: NRTM4DeltaHeader,
    pub entries: Vec<NRTM4DeltaEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NRTM4DeltaHeaderType {
    Delta,
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
    pub header_type: NRTM4DeltaHeaderType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "snake_case")]
pub enum NRTM4DeltaEntry {
    AddModify {
        object: String,
    },
    Delete {
        object_class: String,
        primary_key: String,
    },
}

// #[derive(Debug, Serialize, Deserialize, Validate)]
// #[serde(deny_unknown_fields)]
// pub struct NRTM4DeltaEntry {
//     pub action: NRTM4DeltaEntryAction,

// }

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
#[validate(schema(function = "validate_unf"))]
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

fn validate_unf(unf: &NRTM4UpdateNotificationFile) -> Result<(), ValidationError> {
    if unf.snapshot.version > unf.version {
        return Err(ValidationError::new(
            "Snapshot version can not be higher than Update Notification File version",
        ));
    }
    let delta_versions: Vec<u32> = unf.deltas.iter().map(|delta| delta.version).collect();
    if !is_contiguous_and_ordered(&delta_versions) {
        return Err(ValidationError::new(
            "Delta versions must be sequential contiguous set of version numbers",
        ));
    }
    if let Some(highest_delta_version) = delta_versions.last() {
        if *highest_delta_version > unf.version {
            return Err(ValidationError::new(
                "Delta version can not be higher than Update Notification File version",
            ));
        }
    }
    Ok(())
}
// TODO: timestamp, delta v1, next key, type field in UNF
fn is_contiguous_and_ordered(numbers: &[u32]) -> bool {
    if numbers.is_empty() {
        return true;
    }
    numbers.windows(2).all(|window| window[1] == window[0] + 1)
}
