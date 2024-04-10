use anyhow::anyhow;
use anyhow::Result;
use flate2::read::GzDecoder;
use std::io::Read;

const RS_SYMBOL: u8 = 30; // ASCII RS symbol

pub fn gunzip(input: Vec<u8>) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(&input[..]);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}

pub struct JSONSequenceIterator {
    data: Vec<u8>,
    index: usize,
}

impl JSONSequenceIterator {
    pub fn new(data: Vec<u8>) -> JSONSequenceIterator {
        JSONSequenceIterator { data, index: 1 }
    }
}

impl Iterator for JSONSequenceIterator {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut record_buffer = Vec::new();

        while self.index < self.data.len() {
            let byte = self.data[self.index];
            self.index += 1;

            if byte == RS_SYMBOL {
                if let Ok(s) = String::from_utf8(record_buffer) {
                    return Some(Ok(s));
                } else {
                    return Some(Err(anyhow!("Invalid UTF-8 sequence")));
                }
            } else {
                record_buffer.push(byte);
            }
        }

        if !record_buffer.is_empty() {
            Some(Ok(String::from_utf8_lossy(&record_buffer).to_string()))
        } else {
            None
        }
    }
}
