use crate::nrtm4_types::{
    self, NRTM4DeltaFile, NRTM4File, NRTM4SnapshotFile, NRTM4UpdateNotificationFile,
};
use crate::retrieval::{replace_filename_in_url, retrieve_bytes, retrieve_jsonseq};
use anyhow::anyhow;
use anyhow::Result;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use url::Url;
use validator::Validate;

pub async fn retrieve_validate_nrtmv4(unf_url: Url, source: &str, public_key: &str) -> Result<()> {
    let unf = retrieve_validate_unf(&unf_url, source, public_key).await?;

    retrieve_validate_snapshot(&unf_url, &unf).await?;

    for delta_reference in unf.deltas.iter() {
        retrieve_validate_delta(&unf_url, &unf, delta_reference).await?;
    }
    println!("NRTMv4 syntax is valid.");

    Ok(())
}

async fn retrieve_validate_unf(
    url: &Url,
    source: &str,
    public_key: &str,
) -> Result<NRTM4UpdateNotificationFile> {
    println!(
        "Retrieving and validating Update Notification File from {}",
        url
    );
    let response_bytes = retrieve_bytes(url.clone(), None).await?;
    let verifier = EcdsaJwsAlgorithm::Es256.verifier_from_pem(public_key)?;
    let (payload, header) = josekit::jws::deserialize_compact(&response_bytes, &verifier)?;
    if let Some(algorithm) = header.algorithm() {
        println!(
            "Valid Update Notification File signature with {}",
            algorithm
        );
    }
    let nrtm4_struct: NRTM4UpdateNotificationFile =
        serde_json::from_str(&String::from_utf8_lossy(&payload))?;
    nrtm4_struct.validate()?;

    if nrtm4_struct.source != source {
        return Err(anyhow!(
            "Source does not match: Update Notification File has '{}', expecting '{}'",
            nrtm4_struct.source,
            source
        ));
    }
    Ok(nrtm4_struct)
}

async fn retrieve_validate_snapshot(
    unf_url: &Url,
    unf: &NRTM4UpdateNotificationFile,
) -> Result<(), anyhow::Error> {
    let (header_content, jsonseq_iter) = retrieve_jsonseq(
        replace_filename_in_url(unf_url, &unf.snapshot.url)?,
        Some(&unf.snapshot.hash),
    )
    .await?;
    let snapshot = NRTM4SnapshotFile::from_header_and_records(header_content, jsonseq_iter)?;
    snapshot.validate_unf_consistency(unf)?;
    println!(
        "Snapshot loaded at version {} with {} entries",
        snapshot.header.version,
        snapshot.entries.len()
    );
    Ok(())
}

async fn retrieve_validate_delta(
    unf_url: &Url,
    unf: &NRTM4UpdateNotificationFile,
    delta_reference: &nrtm4_types::NRTM4FileReference,
) -> Result<(), anyhow::Error> {
    let (header_content, jsonseq_iter) = retrieve_jsonseq(
        replace_filename_in_url(unf_url, &delta_reference.url)?,
        Some(&delta_reference.hash),
    )
    .await?;
    let delta = NRTM4DeltaFile::from_header_and_records(header_content, jsonseq_iter)?;
    delta.validate_unf_consistency(unf, delta_reference.version)?;
    println!(
        "Delta loaded for version {} with {} entries",
        delta.header.version,
        delta.entries.len()
    );
    Ok(())
}
