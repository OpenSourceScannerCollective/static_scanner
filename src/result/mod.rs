use std::fmt::{Display, Formatter, Result};

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
    pub line: u16,
    pub verified: bool,
}

impl Display for Secret {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn it_should_display_secret_properly_formatted() {
        let secret = Secret {
            detector_type: DetectorType::Unique("AWS".to_string()),
            decoder_type: DecoderType::Plane,
            raw_result: "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----".to_string(),
            file: "some/file/with/secert/key.priv".to_string(),
            line: 21,
            verified: false,
        };

        let mut given = String::new();
        let Ok(_) = write!(&mut given, "{secret}") else {
            assert!(false);
            return;
        };

        assert_eq!(given,
r#"Found unverified result ?
Detector Type: AWS
DecoderType: Plane
RawResult: -----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----
File: some/file/with/secert/key.priv
Line: 21
"#.to_string());
    }
}
