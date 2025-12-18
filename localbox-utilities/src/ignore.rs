use std::path::Path;

fn normalize_path_str(path: &str) -> String {
    let mut s = path.replace('\\', "/");
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    if cfg!(windows) {
        s = s.to_ascii_lowercase();
    }
    s
}

fn normalize_pattern(pattern: &str) -> String {
    let mut p = pattern.replace('\\', "/");
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    if cfg!(windows) {
        p = p.to_ascii_lowercase();
    }
    p
}

/// Simple glob matcher supporting `*` (any sequence) and `?` (single char).
/// Matching is against normalized `/`-separated paths; on Windows it is case-insensitive.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();

    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut star_text = 0usize;

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }
        if pi < pat.len() && pat[pi] == b'*' {
            while pi < pat.len() && pat[pi] == b'*' {
                pi += 1;
            }
            star = Some(pi);
            star_text = ti;
            continue;
        }
        if let Some(star_pi) = star {
            star_text += 1;
            ti = star_text;
            pi = star_pi;
            continue;
        }
        return false;
    }

    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

pub fn is_ignored_rel_path(rel_path: &str, ignore_patterns: &[String]) -> bool {
    if ignore_patterns.is_empty() {
        return false;
    }
    let rel = normalize_path_str(rel_path);
    ignore_patterns.iter().any(|p| {
        let pat = normalize_pattern(p);
        glob_match(&pat, &rel)
    })
}

pub fn is_ignored_path(path: &Path, ignore_patterns: &[String]) -> bool {
    is_ignored_rel_path(&path.to_string_lossy(), ignore_patterns)
}

#[cfg(test)]
mod tests {
    use super::is_ignored_rel_path;

    #[test]
    fn matches_simple_globs() {
        let patterns = vec![
            "**/*.tmp".to_string(),
            ".git/*".to_string(),
            "Thumbs.db".to_string(),
        ];
        assert!(is_ignored_rel_path("a/b/c.tmp", &patterns));
        assert!(is_ignored_rel_path(".git/index", &patterns));
        assert!(is_ignored_rel_path("Thumbs.db", &patterns));
        assert!(!is_ignored_rel_path("a/b/c.txt", &patterns));
    }
}
