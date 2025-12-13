use std::path::Path;

use utilities::{FileSystem, VirtualFileSystem};

#[test]
fn write_creates_parents_and_reads_back() {
    let fs = VirtualFileSystem::new();

    fs.write(Path::new("/a/b/c.txt"), b"hello").unwrap();

    let data = fs.read(Path::new("/a/b/c.txt")).unwrap();
    assert_eq!(data, b"hello");

    let md_dir = fs.metadata(Path::new("/a/b")).unwrap();
    assert!(md_dir.is_dir);
    assert!(!md_dir.is_file);

    let md_file = fs.metadata(Path::new("/a/b/c.txt")).unwrap();
    assert!(md_file.is_file);
    assert!(!md_file.is_dir);
    assert_eq!(md_file.len, 5);
}

#[test]
fn read_dir_lists_children() {
    let fs = VirtualFileSystem::new();

    fs.create_dir_all(Path::new("/d/e")).unwrap();
    fs.write(Path::new("/d/e/f1"), b"x").unwrap();
    fs.write(Path::new("/d/e/f2"), b"y").unwrap();

    let mut entries = fs
        .read_dir(Path::new("/d/e"))
        .unwrap()
        .into_iter()
        .map(|e| {
            e.path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .collect::<Vec<_>>();
    entries.sort();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], "f1");
    assert_eq!(entries[1], "f2");
}

#[test]
fn normalizes_dot_dot_segments() {
    let fs = VirtualFileSystem::new();

    fs.write(Path::new("/x/y/../z.txt"), b"ok").unwrap();

    assert_eq!(fs.read(Path::new("/x/z.txt")).unwrap(), b"ok");
    assert!(fs.read(Path::new("/x/y/z.txt")).is_err());
}
