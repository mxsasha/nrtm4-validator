use crate::jsonseq::{gunzip, JSONSequenceIterator};
use anyhow::anyhow;
use anyhow::Result;
use sha256::digest;
use url::Url;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub async fn retrieve_jsonseq(
    url: Url,
    expected_hash: Option<&String>,
) -> Result<(String, JSONSequenceIterator)> {
    println!("Retrieving and validating {}", url);
    let response_bytes = retrieve_bytes(url.clone(), expected_hash).await?;
    let uncompressed_response = if url.as_str().ends_with(".gz") {
        gunzip(response_bytes)?
    } else {
        response_bytes
    };
    let mut iter = JSONSequenceIterator::new(uncompressed_response);
    let header_content: String = iter
        .next()
        .unwrap_or_else(|| Err(anyhow!("No header found")))?;
    Ok((header_content, iter))
}

pub async fn retrieve_bytes(url: Url, expected_hash: Option<&String>) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .build()?;
    let response = client.get(url.clone()).send().await?;
    let content_length = response.content_length();
    let body = response.bytes().await?;
    let response_bytes = body.into_iter().collect();
    if let Some(hash) = expected_hash {
        let actual_hash = digest(&response_bytes);
        if actual_hash != *hash {
            return Err(anyhow!(
                "Invalid hash for URL {} - retrieved {:?} bytes, found hash {}, expected {}",
                url,
                content_length,
                actual_hash,
                hash
            ));
        }
    }
    Ok(response_bytes)
}

pub fn replace_filename_in_url(url: &Url, new_filename: &str) -> Result<Url> {
    let base_url = url.join(".")?;
    let new_url = base_url.join(new_filename)?;
    Ok(new_url)
}
