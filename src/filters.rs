use crate::AppResult;
use serde::{Deserialize, Serialize};
use std::fs::Metadata;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileFilters {
    #[serde(default)]
    pub include_extensions: Vec<String>,
    #[serde(default)]
    pub older_than_days: Option<u32>,
    #[serde(default)]
    pub exclude_names: Vec<String>,
}

impl FileFilters {
    pub fn add_extension(&mut self, input: &str) -> AppResult<()> {
        let extension = input.strip_prefix('.').unwrap_or(input);
        if extension.is_empty()
            || extension.len() > 32
            || !extension
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(
                "extensions must contain 1-32 letters, digits, hyphens, or underscores".into(),
            );
        }
        let normalized = extension.to_ascii_lowercase();
        if !self.include_extensions.contains(&normalized) {
            self.include_extensions.push(normalized);
        }
        self.validate()
    }

    pub fn add_exclusion(&mut self, pattern: &str) -> AppResult<()> {
        if pattern.is_empty()
            || pattern.len() > 128
            || pattern
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '\\' | '/' | ':' | '<' | '>' | '"' | '|'))
        {
            return Err("name exclusions must be 1-128 characters without path separators or control characters".into());
        }
        if !self.exclude_names.iter().any(|item| item == pattern) {
            self.exclude_names.push(pattern.to_owned());
        }
        self.validate()
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.include_extensions.len() > 32 || self.exclude_names.len() > 32 {
            return Err("a profile supports at most 32 extensions and 32 name exclusions".into());
        }
        if self
            .older_than_days
            .is_some_and(|days| !(1..=36_500).contains(&days))
        {
            return Err("file age must be 1-36500 days".into());
        }
        for extension in &self.include_extensions {
            if extension.is_empty()
                || extension.len() > 32
                || !extension
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            {
                return Err("profile contains an invalid extension".into());
            }
        }
        for pattern in &self.exclude_names {
            if pattern.is_empty()
                || pattern.len() > 128
                || pattern.chars().any(|ch| {
                    ch.is_control() || matches!(ch, '\\' | '/' | ':' | '<' | '>' | '"' | '|')
                })
            {
                return Err("profile contains an invalid name exclusion".into());
            }
        }
        Ok(())
    }

    pub fn matches(&self, path: &Path, metadata: &Metadata, now: SystemTime) -> AppResult<bool> {
        if !self.include_extensions.is_empty() {
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                return Ok(false);
            };
            if !self
                .include_extensions
                .iter()
                .any(|value| value.eq_ignore_ascii_case(extension))
            {
                return Ok(false);
            }
        }
        if let Some(days) = self.older_than_days {
            let cutoff = now
                .checked_sub(Duration::from_secs(u64::from(days) * 86_400))
                .ok_or("file age cutoff is unavailable")?;
            if metadata.modified()? > cutoff {
                return Ok(false);
            }
        }
        if !self.exclude_names.is_empty() {
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                return Ok(false);
            };
            if self
                .exclude_names
                .iter()
                .any(|pattern| wildcard_match(pattern, name))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    let name: Vec<char> = name.to_lowercase().chars().collect();
    let mut matched = vec![false; name.len() + 1];
    matched[0] = true;
    for token in pattern.to_lowercase().chars() {
        if token == '*' {
            for index in 1..matched.len() {
                matched[index] = matched[index] || matched[index - 1];
            }
        } else {
            for index in (1..matched.len()).rev() {
                matched[index] = matched[index - 1] && (token == '?' || token == name[index - 1]);
            }
            matched[0] = false;
        }
    }
    matched[name.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_only_match_a_single_file_name() {
        assert!(wildcard_match("report-*.TXT", "Report-2026.txt"));
        assert!(wildcard_match("backup-?.zip", "backup-1.zip"));
        assert!(!wildcard_match("backup-?.zip", "backup-10.zip"));
        assert!(!wildcard_match("*.tmp", "keep.txt"));
        assert!(wildcard_match("*", "any-name"));
    }

    #[test]
    fn filter_inputs_are_bounded_and_names_cannot_be_paths() {
        let mut filters = FileFilters::default();
        filters.add_extension(".LOG").unwrap();
        filters.add_extension("log").unwrap();
        assert_eq!(filters.include_extensions, vec!["log"]);
        assert!(filters.add_extension("../txt").is_err());
        assert!(filters.add_exclusion("../private*").is_err());
        filters.older_than_days = Some(0);
        assert!(filters.validate().is_err());
    }
}
