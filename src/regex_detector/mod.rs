use std::collections::{HashMap, HashSet};
use aho_corasick::AhoCorasick;
use regex::{RegexBuilder, Regex};
use serde::{Deserialize, Serialize};
use serde_yaml::from_str as yaml_from_str;
use std::fs::read_to_string;
use std::path::Path;
use std::io::{Result as IoResult, Error, ErrorKind};
use crate::result::{DecoderType, DetectorType, Secret};
use crate::lines::LinesEndsProvider;
use std::fmt::Debug;

#[cfg(test)]
mod mod_test;

/// Scanner offers scanning capabilities.
/// Scanning returns result of all found secrets locations.
///
pub trait Scanner: Debug {
    fn scan(&self, s: &str, file: &str, lines_ends: &impl LinesEndsProvider) -> Result<Vec<Secret>, String>;
}

/// KeyWithSecrets represpresents keys names that can heve cerain secret schema.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysWithSecrets {
    keys: Option<Vec<String>>,
    secrets: Option<Vec<String>>,
}

/// Schema represents a secret schema which is a set of known words that exist in the secret.
/// It can be created from yaml file with specific schema.
///
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    name: String,
    secret_regexes: Option<Vec<String>>,
    keys_with_secerets: Option<Vec<KeysWithSecrets>>,
    keys_required: Option<Vec<String>>,
}

impl Schema {
    /// Reads Schema configurations from yaml file.
    ///
    #[inline(always)]
    pub fn read_from_yaml_file(path: &Path) -> IoResult<Vec<Schema>> {
        let yaml_cfg = read_to_string(path)?;
        let Ok(cfg) = yaml_from_str(&yaml_cfg) else {
            return Err(Error::new(ErrorKind::Other, format!("cannot deserialize")));
        };
        Ok(cfg)
    }
}

#[derive(Debug)]
struct Variables {
    aho: AhoCorasick,
    reg: Vec<Regex>,
}

#[derive(Debug)]
pub struct Pattern {
    name: String,
    secret_regex: Vec<Regex>,
    variables: Vec<Variables>,
    keys_required: Vec<String>,
}

impl Scanner for Pattern {
    #[inline(always)]
    fn scan(&self, s: &str, file: &str, line_ends: &impl LinesEndsProvider) -> Result<Vec<Secret>, String> {
        let mut detector = Detection::new(self, s, file, line_ends);
        detector.detect()
    }
}

#[derive(Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SecretPosition{
    start: usize,
    end: usize,
}

impl SecretPosition {
    #[inline(always)]
    fn new(start: usize, end: usize) -> Self {
        Self{start, end}
    }
}

#[derive(Hash, Debug, PartialEq, Eq)]
struct SecretItem<'a> {
    key: &'a str,
    value: &'a str,
}

#[derive(Debug)]
struct Detection<'a, T: LinesEndsProvider> {
    buf: &'a str,
    file: &'a str,
    unique: HashMap<SecretPosition, SecretItem<'a>>,
    scanner: &'a Pattern,
    line_ends: &'a T,
}

impl<'a, T> Detection<'a, T>
where T: LinesEndsProvider,
{
    #[inline(always)]
    fn new(s: &'a Pattern, buf: &'a str, file: &'a str, line_ends: &'a T) -> Self {
        Self {
            buf,
            file,
            unique: HashMap::new(),
            scanner: s,
            line_ends,
        }
    }

    #[inline(always)]
    fn detect(&'a mut self) -> Result<Vec<Secret>, String> {
        for variable in self.scanner.variables.iter() {
            for key in variable.aho.find_overlapping_iter(self.buf) {
                'regs_loop: for r in variable.reg.iter() {
                    let Some(secrets) = r.captures(&self.buf[key.end()..]) else {
                        continue 'regs_loop;
                    };
                    let Some(secret) = secrets.get(0) else {
                        continue 'regs_loop;
                    };
                    let position = SecretPosition::new(key.end()+secret.start(), key.end()+secret.end());
                    if self.unique.contains_key(&position) {
                        continue 'regs_loop;
                    }
                    self.unique.insert(position, SecretItem{key: &self.buf[key.start()..key.end()], value: secret.as_str()});
                }
            }
        }

        'regex_loop: for r in self.scanner.secret_regex.iter() {
            let Some(secrets) = r.captures(&self.buf) else {
                continue 'regex_loop;
            };
            let Some(secret) = secrets.get(0) else {
              continue 'regex_loop;
            };
            let position = SecretPosition::new(secret.start(), secret.end());
            if self.unique.contains_key(&position) {
                continue 'regex_loop;
            }
            self.unique.insert(position, SecretItem{key: "secret", value: secret.as_str()});
        }

        Ok(self.collect())
    }

    #[inline(always)]
    fn collect(&self) -> Vec<Secret> {
        let mut secrets = Vec::new();
        let mut positions = Vec::new();

        for (k, _v) in self.unique.iter() {
           positions.push(k);
        }
        positions.sort();

        let mut keys: HashSet<&str> = HashSet::new();
        let mut raw: Vec<&SecretItem> = Vec::new();
        let mut start: Option<usize> = None;

        'positions_loop: for position in positions.iter() {
            let Some(item) = self.unique.get(&position) else {
                continue 'positions_loop;
            };

            match start {
                Some(_) => (),
                None => start = Some(position.start),
            };

            if keys.insert(&item.key) {
                raw.push(&item);
                continue 'positions_loop;
            }

            let mut found_count = self.scanner.keys_required.len();
            for required in self.scanner.keys_required.iter() {
                for k in raw.iter() { // TODO: if number of keys is large enough this loop is going to be a bottleneck, use raw_unique_keys HashSet that contains only keys for fast lookup.
                    if required.eq(k.key) {
                       found_count -= 1;
                    }
                }
            }
            if found_count != 0 {
                continue 'positions_loop;
            }

            let secret = Secret {
                detector_type: DetectorType::Unique(self.scanner.name.clone()),
                decoder_type: DecoderType::Plane,
                raw_result: Self::stringify(&raw),
                file: self.file.to_string(),
                line: self.line_ends.get_line(start.unwrap_or_default()).unwrap_or_default(),
                verified: false,
            };

            start = Some(position.start);

            secrets.push(secret);

            keys.clear();
            keys.insert(&item.key);

            raw.clear();
            raw.push(&item);
        }

        if raw.len() > 0 {
            let mut found_count = self.scanner.keys_required.len();
            for required in self.scanner.keys_required.iter() {
                for k in raw.iter() {
                    if required.eq(k.key) {
                       found_count -= 1;
                    }
                }
            }
            if found_count != 0 {
                return secrets;
            }

            let secret = Secret {
                detector_type: DetectorType::Unique(self.scanner.name.clone()),
                decoder_type: DecoderType::Plane,
                raw_result: Self::stringify(&raw),
                file: self.file.to_string(),
                line: self.line_ends.get_line(start.unwrap_or_default()).unwrap_or_default(),
                verified: false,
            };
            secrets.push(secret);
        }

        secrets
    }

    #[inline(always)]
    fn stringify(raw: &[&SecretItem]) -> String {
        let mut result: String = String::new();
        for item in raw.iter() {
            if result.len() > 0 {
                result.push_str(", ");
            }
            result.push_str(&format!("{}: {}", item.key, item.value));
        }

        result
    }
}

/// Builds the detector.
#[derive(Debug, Clone)]
pub struct Builder {
    name: Option<String>,
    secret_regexes: Vec<String>,
    variables: Vec<(Vec<String>, Vec<String>)>,
    keys_required: Vec<String>,
}

impl Builder {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            name: None,
            secret_regexes: Vec::new(),
            variables: Vec::new(),
            keys_required: Vec::new(),
        }
    }

    /// Names the scanner.
    ///
    #[inline(always)]
    pub fn with_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.to_string());
        self
    }

    /// Populates secret regexes with given regexes.
    /// Secret regexes are regexes to be precompiled to much a token as a secret.
    ///
    #[inline(always)]
    pub fn with_secret_regexes(&mut self, patterns: &[&str]) -> &mut Self {
        for pattern in patterns.iter() {
            self.secret_regexes.push(pattern.to_string());
        }
        self
    }

    /// Populates variables with given patterns.
    /// Variables will be precompiled to much a token as a variable.
    ///
    #[inline(always)]
    pub fn with_variables(&mut self, patterns: &[&str], regexes: &[&str]) -> &mut Self {
        let mut variables = (Vec::new(), Vec::new());
        for pattern in patterns.iter() {
            variables.0.push(pattern.to_string());
        }
        for reg in regexes.iter() {
            variables.1.push(reg.to_string());
        }
        self.variables.push(variables);
        self
    }

    /// Populates keys required to filter true positive secrets.
    ///
    #[inline(always)]
    pub fn with_keys_required(&mut self, keys: &[&str]) -> &mut Self {
        for key in keys.iter() {
            self.keys_required.push(key.to_string());
        }
        self
    }

    /// Tries to build a scanner.
    ///
    #[inline(always)]
    pub fn try_build_scanner(&self) -> Result<Pattern, String> {
        let mut variables_schema = Vec::new();
        for variables in self.variables.iter() {
            if variables.0.len() > 0 && variables.1.len() > 0 {
                let res = AhoCorasick::new(&variables.0);
                if let Err(err) = res {
                    return Err(err.to_string());
                }
                let Ok(aho) = res else {
                    return Err("Failed to create AhoCorasik".to_string());
                };
                let mut reg = Vec::new();
                'regex_loop: for rgx in variables.1.iter() {
                    let res = RegexBuilder::new(rgx).build();
                    if let Ok(r) = res {
                        reg.push(r);
                        continue 'regex_loop;
                    }
                    if let Err(e) = res {
                        return Err(e.to_string());
                    }
                }
                variables_schema.push(Variables {
                    aho,
                    reg,
                });
            }
        }

        let mut secret_regex = Vec::new();

        for pattern in self.secret_regexes.iter() {
            let res = RegexBuilder::new(pattern).build();
            if let Ok(regex) = res {
                secret_regex.push(regex);
                continue;
            }
            if let Err(e) = res {
                return Err(e.to_string());
            }
        }

        Ok(Pattern {
            name: match &self.name {
                Some(name) => name.clone(),
                None => "".to_string(),
            },
            secret_regex,
            variables: variables_schema,
            keys_required: self.keys_required.to_owned(),
        })
   }
}

impl TryFrom<&Schema> for Pattern {
    type Error = Error;

    #[inline(always)]
    fn try_from(s: &Schema) -> Result<Self, Self::Error> {
        let mut keys_required: Vec<&str> = Vec::new();
        if let Some(keys) = &s.keys_required {
            for key in keys.iter() {
                keys_required.push(key);
            }
        }

        let mut secrets: Vec<&str> = Vec::new();
        if let Some(secret_regexes) = &s.secret_regexes{
            for secret in secret_regexes.iter() {
                secrets.push(secret);
            }
        }
        let mut keys_w_secrets: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();

        if let Some(keys_with_secrets) = &s.keys_with_secerets {
            for kws in keys_with_secrets.iter() {
                let mut pattern: (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
                let Some(keys) = &kws.keys else {
                    continue;
                };
                for k in keys.iter() {
                    pattern.0.push(k);
                }
                let Some(secrets) = &kws.secrets else {
                    continue;
                };
                for s in secrets.iter() {
                    pattern.1.push(s);
                }
                keys_w_secrets.push(pattern);
            }
        }

        let mut builder = Builder::new();
        builder.with_name(&s.name);
        builder.with_secret_regexes(&secrets);
        builder.with_keys_required(&keys_required);
        for kws in keys_w_secrets.iter() {
            builder.with_variables(&kws.0, &kws.1);
        }

        let Ok(scanner) = builder.try_build_scanner() else {
            return Err(Error::new(ErrorKind::InvalidData, "cannot build scanner from schema"));
        };

        Ok(scanner)
    }
}
