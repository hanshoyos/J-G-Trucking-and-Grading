use std::fs;
use std::path::Path;
use std::sync::Arc;

use tracing::{debug, warn};

use super::{Rule, RuleRef};

/// Load all `*.yaml` and `*.yml` files from `dir` as correlation rules.
/// Errors on individual files are logged and skipped.
pub fn load_yaml_rules(dir: &str) -> anyhow::Result<Vec<RuleRef>> {
    let path = Path::new(dir);
    if !path.exists() {
        debug!(dir = %dir, "Rules directory does not exist, skipping");
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();

    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory entry: {e}");
                continue;
            }
        };

        let file_path = entry.path();
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = ?file_path, "Failed to read rule file: {e}");
                continue;
            }
        };

        // Support files that contain a single rule or a list of rules.
        let parsed: Vec<Rule> = if content.trim_start().starts_with('-') {
            match serde_yaml::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    warn!(path = ?file_path, "Failed to parse rule list: {e}");
                    continue;
                }
            }
        } else {
            match serde_yaml::from_str::<Rule>(&content) {
                Ok(r) => vec![r],
                Err(e) => {
                    warn!(path = ?file_path, "Failed to parse rule: {e}");
                    continue;
                }
            }
        };

        for rule in parsed {
            debug!(name = %rule.name, "Loaded YAML rule");
            rules.push(Arc::new(rule));
        }
    }

    Ok(rules)
}
