use std::fmt::{Display, Formatter, Result};

#[cfg(test)]
mod mod_test;

/// Describes detector type.
///
#[derive(Debug, Serialize, Deserialize, Display, Clone)]
#[display(fmt = "{}")]
pub enum DetectorType {
    Unique(String)
}

/// Describes decoder type.
///
#[derive(Debug, Serialize, Deserialize, Display, Clone)]
#[display(fmt = "{}")]
pub enum DecoderType {
    #[display(fmt="Plane")]
    Plane,
    #[display(fmt="Base64")]
    Base64,
    #[display(fmt="JWT")]
    Jwt,
}


use serde::{Deserialize, Serialize};
/// Result of the secret finding.
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secret {
    pub detector_type: DetectorType,
    pub decoder_type: DecoderType,
    pub raw_result: String,
    pub file: String,
    pub line: usize,
    pub verified: bool,
}

impl Display for Secret {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> Result {
        let verified: &str = match self.verified {
            true => "Found verified result !",
            _ => "Found unverified result ?",
        };
        write!(f, "{}\nDetector Type: {}\nDecoderType: {}\nRawResult: \"{}\"\nFile: {}\nLine: {}\n",
            verified, self.detector_type, self.decoder_type, self.raw_result,
            self.file, self.line,
        )
    }
}
