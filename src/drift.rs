//! `sorseal drift` — compare two sealed records and report exactly what moved.
//!
//! Two kinds of subject are accepted: a sealed provenance record
//! (`sorseal.provenance.json`) and a manifest (`sorseal.toml`). Comparing two
//! provenance records answers "what changed between the build I sealed last
//! week and the one I sealed today"; comparing a manifest against a provenance
//! answers "has my configuration drifted from what I actually sealed".
//!
//! Seal timestamps (`built_at`, `analyzed_at`) are deliberately excluded from
//! the comparison: they differ on every seal by construction, so including
//! them would make every pair of seals report drift.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::manifest::Manifest;
use crate::provenance::{ArtifactProvenance, Provenance};

/// Placeholder shown when a side has no value for a field.
pub const ABSENT: &str = "(absent)";

/// Which side an entry was found on, or whether it changed in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Added,
    Removed,
    Changed,
}

/// A single field that differs between the two sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    /// Value on the left side, or [`ABSENT`] when the left has no such field.
    pub left: String,
    /// Value on the right side, or [`ABSENT`] when the right has no such field.
    pub right: String,
}

/// An artifact (or manifest entry) present on one side or changed between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryDiff {
    pub id: String,
    pub status: Status,
    pub fields: Vec<FieldDiff>,
}

/// A top-level record field (project, toolchain, git) that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextDiff {
    pub field: String,
    pub left: String,
    pub right: String,
}

/// How many differences of each kind were found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub context: usize,
}

/// The full comparison result. Serializes directly to the `--format json`
/// document, so the console and JSON renderings can never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    pub project: String,
    /// Path of the left-hand subject, as given on the command line.
    pub left: String,
    /// Path of the right-hand subject, as given on the command line.
    pub right: String,
    /// True when nothing differs, seal timestamps excluded.
    pub identical: bool,
    pub counts: Counts,
    pub context: Vec<ContextDiff>,
    pub entries: Vec<EntryDiff>,
}

/// One side of a comparison: a sealed provenance record or a `sorseal.toml`.
#[derive(Debug)]
pub enum Subject {
    Provenance(Provenance),
    Manifest(Manifest),
}

impl Subject {
    /// Load either subject type, discriminating on the on-disk format.
    ///
    /// A provenance record is JSON and always starts with an object; a
    /// manifest is TOML. Anything else is reported with the path so the user
    /// knows which of the two arguments was wrong.
    pub fn load(path: &Path) -> Result<Subject> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if raw.trim_start().starts_with('{') {
            Ok(Subject::Provenance(Provenance::load(path)?))
        } else {
            Ok(Subject::Manifest(Manifest::load(path)?))
        }
    }

    /// A short human label for the subject kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Subject::Provenance(_) => "provenance",
            Subject::Manifest(_) => "manifest",
        }
    }

    /// The project name recorded on this side.
    pub fn project(&self) -> &str {
        match self {
            Subject::Provenance(p) => &p.project,
            Subject::Manifest(m) => &m.project.name,
        }
    }

    /// Top-level record fields, as a sorted key/value map.
    fn context(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        match self {
            Subject::Provenance(p) => {
                m.insert("project".to_string(), p.project.clone());
                m.insert("toolchain".to_string(), p.toolchain.clone());
                if p.git.present {
                    m.insert("git.commit".to_string(), p.git.commit.clone());
                    m.insert("git.clean".to_string(), p.git.clean.to_string());
                } else {
                    m.insert("git".to_string(), "not a git repository".to_string());
                }
            }
            Subject::Manifest(m2) => {
                m.insert("project".to_string(), m2.project.name.clone());
            }
        }
        m
    }

    /// Per-entry field maps keyed by artifact id, sorted by id.
    fn entries(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        match self {
            Subject::Provenance(p) => {
                for a in &p.artifacts {
                    out.insert(a.id.clone(), provenance_fields(&p.analysis, a));
                }
            }
            Subject::Manifest(m) => {
                for a in &m.artifacts {
                    let mut fields = BTreeMap::new();
                    // Normalised to the provenance spelling so a manifest can
                    // be compared against the record it produced.
                    fields.insert("command".to_string(), a.build_command.clone());
                    fields.insert("wasm_path".to_string(), a.wasm_path.display().to_string());
                    fields.insert(
                        "source_root".to_string(),
                        a.source_root.display().to_string(),
                    );
                    out.insert(a.id.clone(), fields);
                }
            }
        }
        out
    }
}

/// The comparable fields of a sealed artifact.
///
/// `built_at` is intentionally omitted: it is a timestamp, not a property of
/// the build, and would otherwise flag every comparison as drift. Analysis
/// digests are included when present, so a re-sealed analysis is visible.
fn provenance_fields(
    analysis: &[crate::provenance::ArtifactAnalysis],
    a: &ArtifactProvenance,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("command".to_string(), a.command.clone());
    m.insert("wasm_path".to_string(), a.wasm_path.clone());
    m.insert("source_root".to_string(), a.source_root.clone());
    m.insert("wasm_sha256".to_string(), a.wasm_sha256.clone());
    m.insert("wasm_size".to_string(), a.wasm_size.to_string());
    m.insert("source_sha256".to_string(), a.source_sha256.clone());
    if let Some(an) = analysis.iter().find(|x| x.id == a.id) {
        m.insert("analysis.digest".to_string(), an.digest.clone());
        m.insert("analysis.findings".to_string(), an.findings.to_string());
        m.insert(
            "analysis.worst_severity".to_string(),
            an.worst_severity.clone(),
        );
    }
    m
}

/// Compare two loaded subjects.
///
/// Differences are reported in a stable order: context fields first (sorted by
/// field name), then entries (sorted by artifact id), so the output is
/// byte-for-byte reproducible for a given pair of inputs.
pub fn compare(
    left: &Subject,
    right: &Subject,
    left_label: &str,
    right_label: &str,
) -> DriftReport {
    let mut context = Vec::new();
    let lc = left.context();
    let rc = right.context();
    for key in lc.keys().chain(rc.keys()).collect::<BTreeSet<_>>() {
        let l = lc.get(key).cloned().unwrap_or_else(|| ABSENT.to_string());
        let r = rc.get(key).cloned().unwrap_or_else(|| ABSENT.to_string());
        if l != r {
            context.push(ContextDiff {
                field: key.clone(),
                left: l,
                right: r,
            });
        }
    }

    let le = left.entries();
    let re = right.entries();
    let mut entries = Vec::new();
    let mut counts = Counts {
        context: context.len(),
        ..Counts::default()
    };

    for id in le.keys().chain(re.keys()).collect::<BTreeSet<_>>() {
        let l = le.get(id);
        let r = re.get(id);
        match (l, r) {
            (Some(l), None) => {
                counts.removed += 1;
                entries.push(EntryDiff {
                    id: id.clone(),
                    status: Status::Removed,
                    fields: field_diffs(l, &BTreeMap::new()),
                });
            }
            (None, Some(r)) => {
                counts.added += 1;
                entries.push(EntryDiff {
                    id: id.clone(),
                    status: Status::Added,
                    fields: field_diffs(&BTreeMap::new(), r),
                });
            }
            (Some(l), Some(r)) => {
                let fields = field_diffs(l, r);
                if !fields.is_empty() {
                    counts.changed += 1;
                    entries.push(EntryDiff {
                        id: id.clone(),
                        status: Status::Changed,
                        fields,
                    });
                }
            }
            (None, None) => unreachable!("id came from one of the two maps"),
        }
    }

    let identical = entries.is_empty() && context.is_empty();
    DriftReport {
        project: left.project().to_string(),
        left: left_label.to_string(),
        right: right_label.to_string(),
        identical,
        counts,
        context,
        entries,
    }
}

/// Field-level diff of two entries, sorted by field name.
///
/// A field present on only one side is reported against [`ABSENT`] on the
/// other, which is how a manifest (no digests) compares against a provenance
/// record (digests) and how a newly-sealed analysis shows up.
fn field_diffs(l: &BTreeMap<String, String>, r: &BTreeMap<String, String>) -> Vec<FieldDiff> {
    let mut out = Vec::new();
    for key in l.keys().chain(r.keys()).collect::<BTreeSet<_>>() {
        let lv = l.get(key).cloned().unwrap_or_else(|| ABSENT.to_string());
        let rv = r.get(key).cloned().unwrap_or_else(|| ABSENT.to_string());
        if lv != rv {
            out.push(FieldDiff {
                field: key.clone(),
                left: lv,
                right: rv,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{ArtifactAnalysis, GitState};

    fn artifact(id: &str, wasm: &str) -> ArtifactProvenance {
        ArtifactProvenance {
            id: id.to_string(),
            command: "cargo build --release".to_string(),
            wasm_path: "target/x.wasm".to_string(),
            wasm_sha256: wasm.to_string(),
            wasm_size: 10,
            source_root: ".".to_string(),
            source_sha256: "e".repeat(64),
            built_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn provenance(artifacts: Vec<ArtifactProvenance>, toolchain: &str) -> Provenance {
        Provenance {
            format: crate::provenance::FORMAT.to_string(),
            version: 1,
            project: "demo".to_string(),
            toolchain: toolchain.to_string(),
            git: GitState {
                present: true,
                commit: "a".repeat(40),
                clean: true,
            },
            artifacts,
            analysis: Vec::new(),
        }
    }

    /// Two provenance subjects without touching the filesystem.
    fn pair(l: Provenance, r: Provenance) -> DriftReport {
        compare(
            &Subject::Provenance(l),
            &Subject::Provenance(r),
            "a.json",
            "b.json",
        )
    }

    #[test]
    fn identical_seals_report_no_drift() {
        let a = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.95.0");
        let b = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.95.0");
        let r = pair(a, b);
        assert!(r.identical);
        assert!(r.entries.is_empty());
        assert!(r.context.is_empty());
        assert_eq!(r.counts, Counts::default());
    }

    #[test]
    fn seal_timestamps_are_not_drift() {
        // built_at differs on every seal; it must never flag drift on its own.
        let mut a = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.95.0");
        let mut b = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.95.0");
        a.artifacts[0].built_at = "2026-01-01T00:00:00Z".into();
        b.artifacts[0].built_at = "2026-06-06T06:06:06Z".into();
        assert!(pair(a, b).identical);
    }

    #[test]
    fn added_artifact_is_reported() {
        let a = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let b = provenance(
            vec![
                artifact("echo", &"f".repeat(64)),
                artifact("vault", &"0".repeat(64)),
            ],
            "t",
        );
        let r = pair(a, b);
        assert!(!r.identical);
        assert_eq!(r.counts.added, 1);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].id, "vault");
        assert_eq!(r.entries[0].status, Status::Added);
        // The added side carries its values; the missing side is ABSENT.
        assert_eq!(r.entries[0].fields.len(), 6);
        assert!(r.entries[0].fields.iter().all(|f| f.left == ABSENT));
        assert!(r.entries[0]
            .fields
            .iter()
            .any(|f| f.field == "wasm_sha256" && f.right == "0".repeat(64)));
    }

    #[test]
    fn removed_artifact_is_reported() {
        let a = provenance(
            vec![
                artifact("echo", &"f".repeat(64)),
                artifact("vault", &"0".repeat(64)),
            ],
            "t",
        );
        let b = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let r = pair(a, b);
        assert_eq!(r.counts.removed, 1);
        assert_eq!(r.entries[0].id, "vault");
        assert_eq!(r.entries[0].status, Status::Removed);
        assert!(r.entries[0].fields.iter().all(|f| f.right == ABSENT));
    }

    #[test]
    fn digest_change_is_reported_with_both_values() {
        let a = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let b = provenance(vec![artifact("echo", &"0".repeat(64))], "t");
        let r = pair(a, b);
        assert_eq!(r.counts.changed, 1);
        assert_eq!(r.entries[0].status, Status::Changed);
        let d = r.entries[0]
            .fields
            .iter()
            .find(|f| f.field == "wasm_sha256")
            .expect("wasm_sha256 differs");
        assert_eq!(d.left, "f".repeat(64));
        assert_eq!(d.right, "0".repeat(64));
        // Only the digest moved — the other five fields are untouched.
        assert_eq!(r.entries[0].fields.len(), 1);
    }

    #[test]
    fn source_digest_change_is_reported() {
        let mut a = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let mut b = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        a.artifacts[0].source_sha256 = "e".repeat(64);
        b.artifacts[0].source_sha256 = "1".repeat(64);
        let r = pair(a, b);
        assert_eq!(r.counts.changed, 1);
        assert!(r.entries[0]
            .fields
            .iter()
            .any(|f| f.field == "source_sha256"));
    }

    #[test]
    fn context_differences_are_reported_separately() {
        let a = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.95.0");
        let b = provenance(vec![artifact("echo", &"f".repeat(64))], "rustc 1.96.0");
        let r = pair(a, b);
        assert!(!r.identical);
        assert!(r.entries.is_empty());
        assert_eq!(r.counts.context, 1);
        assert_eq!(r.context[0].field, "toolchain");
        assert_eq!(r.context[0].left, "rustc 1.95.0");
        assert_eq!(r.context[0].right, "rustc 1.96.0");
    }

    #[test]
    fn output_order_is_stable() {
        // Entry ids and field names must sort identically regardless of the
        // order the artifacts were recorded in.
        let a = provenance(
            vec![
                artifact("zeta", &"f".repeat(64)),
                artifact("alpha", &"f".repeat(64)),
            ],
            "t",
        );
        let b = provenance(
            vec![
                artifact("alpha", &"0".repeat(64)),
                artifact("zeta", &"f".repeat(64)),
            ],
            "t",
        );
        let r = pair(a, b);
        let ids: Vec<&str> = r.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["alpha"]);
    }

    #[test]
    fn json_document_has_stable_shape() {
        let a = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let b = provenance(vec![artifact("echo", &"0".repeat(64))], "t");
        let r = pair(a, b);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["project"], "demo");
        assert_eq!(v["left"], "a.json");
        assert_eq!(v["right"], "b.json");
        assert_eq!(v["identical"], false);
        assert_eq!(v["counts"]["changed"], 1);
        assert_eq!(v["entries"][0]["id"], "echo");
        assert_eq!(v["entries"][0]["status"], "changed");
        assert_eq!(v["entries"][0]["fields"][0]["field"], "wasm_sha256");
        // Round-trips into the same structure the console renderer reads.
        let back: DriftReport = serde_json::from_value(v).unwrap();
        assert_eq!(back.counts.changed, 1);
    }

    #[test]
    fn analysis_digest_appears_in_the_entry() {
        let mut a = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        let mut b = provenance(vec![artifact("echo", &"f".repeat(64))], "t");
        a.analysis = vec![ArtifactAnalysis {
            id: "echo".into(),
            findings: 3,
            worst_severity: "High".into(),
            digest: "a".repeat(64),
            analyzed_at: "2026-01-01T00:00:00Z".into(),
        }];
        b.analysis = vec![ArtifactAnalysis {
            id: "echo".into(),
            findings: 3,
            worst_severity: "High".into(),
            digest: "b".repeat(64),
            analyzed_at: "2026-01-01T00:00:00Z".into(),
        }];
        let r = pair(a, b);
        assert_eq!(r.counts.changed, 1);
        let d = r.entries[0]
            .fields
            .iter()
            .find(|f| f.field == "analysis.digest")
            .expect("analysis digest compared");
        assert_eq!(d.left, "a".repeat(64));
        assert_eq!(d.right, "b".repeat(64));
        // analyzed_at is a timestamp and must not contribute.
        assert!(!r.entries[0]
            .fields
            .iter()
            .any(|f| f.field.contains("analyzed_at")));
    }

    #[test]
    fn manifest_compares_against_provenance() {
        use crate::manifest::{Artifact, Project};

        let m = Manifest {
            project: Project {
                name: "demo".to_string(),
            },
            artifacts: vec![Artifact {
                id: "echo".to_string(),
                build_command: "cargo build --release".to_string(),
                wasm_path: "target/x.wasm".into(),
                source_root: ".".into(),
            }],
        };
        let p = provenance(vec![artifact("echo", &"f".repeat(64))], "t");

        // Shared config fields match; the provenance-only digests are absent
        // on the manifest side and are reported as such.
        let r = compare(
            &Subject::Manifest(m),
            &Subject::Provenance(p),
            "sorseal.toml",
            "sorseal.provenance.json",
        );
        assert!(!r.identical);
        let fields = &r.entries[0].fields;
        assert_eq!(r.entries[0].status, Status::Changed);
        assert!(fields
            .iter()
            .any(|f| f.field == "wasm_sha256" && f.left == ABSENT && f.right == "f".repeat(64)));
        // command/wasm_path/source_root line up, so they are not differences.
        assert!(!fields.iter().any(|f| f.field == "command"));
        assert!(!fields.iter().any(|f| f.field == "wasm_path"));
        assert!(!fields.iter().any(|f| f.field == "source_root"));
    }

    #[test]
    fn load_rejects_a_path_that_does_not_exist() {
        let err = Subject::load(Path::new("/nonexistent/sorseal.provenance.json"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to read"), "{err}");
    }
}
