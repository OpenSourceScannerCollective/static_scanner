use crate::regex_detector::{Schema, Scanner, Pattern};
use crate::lines::LinesEnds;
use crate::result::Secret;
use std::io::Result as IoResult;
use std::path::Path;

#[derive(Debug)]
enum ScannerWrapper {
    Regex(Pattern),
}

impl Scanner for ScannerWrapper {
    #[inline(always)]
    fn scan(&self, s: &str, file: &str, lines_ends: &impl crate::lines::LinesEndsProvider) -> Result<Vec<Secret>, String> {
        match self {
            Self::Regex(scan) => scan.scan(s, file, lines_ends),
        }
    }
}

#[derive(Debug)]
pub struct Inspector {
    scanners: Vec<ScannerWrapper>,
}

impl Inspector {
    #[inline(always)]
    pub fn try_new(path_to_config_yaml: &str) -> IoResult<Self> {
        let path = Path::new(path_to_config_yaml);
        let mut scanners: Vec<ScannerWrapper> = Vec::new();
        for schema in Schema::read_from_yaml_file(path)?.iter() {
            let s: ScannerWrapper = ScannerWrapper::Regex(schema.try_into()?);
            scanners.push(s);
        }
        Ok(Self {
            scanners,
        })
    }
}

impl Inspector {
    #[inline(always)]
    pub fn inspect(&self, s: &str, file: &str) -> Result<Vec<Secret>, String> {
        let line_ends = LinesEnds::from_str(s);
        let mut results: Vec<Secret> = Vec::new();
        for scanner in self.scanners.iter() {
            results.extend(scanner.scan(s, file, &line_ends)?);
        }
        Ok(results)
    }
}
