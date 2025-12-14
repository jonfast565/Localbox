use std::collections::{BTreeMap, HashMap};
use std::io;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct FsMetadata {
    pub is_file: bool,
    pub is_dir: bool,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: PathBuf,
    pub metadata: FsMetadata,
}

pub trait FileSystem: Send + Sync {
    fn metadata(&self, path: &Path) -> io::Result<FsMetadata>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn Read + Send>>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct RealFileSystem;

impl RealFileSystem {
    pub fn new() -> Self {
        Self
    }
}

impl FileSystem for RealFileSystem {
    fn metadata(&self, path: &Path) -> io::Result<FsMetadata> {
        let md = std::fs::metadata(path)?;
        Ok(FsMetadata {
            is_file: md.is_file(),
            is_dir: md.is_dir(),
            len: md.len(),
            modified: md.modified().ok(),
        })
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let entries = std::fs::read_dir(path)?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let md = entry.metadata()?;
            out.push(DirEntry {
                path,
                metadata: FsMetadata {
                    is_file: md.is_file(),
                    is_dir: md.is_dir(),
                    len: md.len(),
                    modified: md.modified().ok(),
                },
            });
        }
        Ok(out)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, data)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn Read + Send>> {
        let f = std::fs::File::open(path)?;
        Ok(Box::new(f))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}

#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    inner: Arc<Mutex<VirtualFsInner>>,
}

#[derive(Debug, Default)]
struct VirtualFsInner {
    nodes: HashMap<PathBuf, VNode>,
    children: HashMap<PathBuf, BTreeMap<String, PathBuf>>,
}

#[derive(Debug, Clone)]
enum VNode {
    File { data: Vec<u8>, modified: SystemTime },
    Dir { modified: SystemTime },
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        let mut inner = VirtualFsInner::default();
        inner.nodes.insert(
            PathBuf::from("/"),
            VNode::Dir {
                modified: SystemTime::now(),
            },
        );
        VirtualFileSystem {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn normalize(path: &Path) -> PathBuf {
        let mut components = Vec::new();
        for comp in path.components() {
            match comp {
                Component::RootDir => {
                    components.clear();
                    components.push(PathBuf::from("/"));
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    components.pop();
                }
                Component::Normal(c) => {
                    let mut p = components.last().cloned().unwrap_or_else(|| PathBuf::from("/"));
                    p.push(c);
                    components.push(p);
                }
                Component::Prefix(_) => {}
            }
        }
        components.last().cloned().unwrap_or_else(|| PathBuf::from("/"))
    }

    fn ensure_parent(&self, inner: &mut VirtualFsInner, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            let norm = Self::normalize(parent);
            if !inner.nodes.contains_key(&norm) {
                inner.nodes.insert(
                    norm.clone(),
                    VNode::Dir {
                        modified: SystemTime::now(),
                    },
                );
            }
        }
        Ok(())
    }
}

impl FileSystem for VirtualFileSystem {
    fn metadata(&self, path: &Path) -> io::Result<FsMetadata> {
        let inner = self.inner.lock().unwrap();
        let norm = Self::normalize(path);
        let node = inner.nodes.get(&norm).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found", norm.display()),
            )
        })?;
        match node {
            VNode::File { data, modified } => Ok(FsMetadata {
                is_file: true,
                is_dir: false,
                len: data.len() as u64,
                modified: Some(*modified),
            }),
            VNode::Dir { modified } => Ok(FsMetadata {
                is_file: false,
                is_dir: true,
                len: 0,
                modified: Some(*modified),
            }),
        }
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let inner = self.inner.lock().unwrap();
        let norm = Self::normalize(path);
        let node = inner.nodes.get(&norm).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found", norm.display()),
            )
        })?;
        match node {
            VNode::Dir { .. } => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} is not a directory", norm.display()),
                ))
            }
        }
        let mut out = Vec::new();
        if let Some(children) = inner.children.get(&norm) {
            for (_name, child_path) in children {
                if let Some(node) = inner.nodes.get(child_path) {
                    match node {
                        VNode::File { data, modified } => out.push(DirEntry {
                            path: child_path.clone(),
                            metadata: FsMetadata {
                                is_file: true,
                                is_dir: false,
                                len: data.len() as u64,
                                modified: Some(*modified),
                            },
                        }),
                        VNode::Dir { modified } => out.push(DirEntry {
                            path: child_path.clone(),
                            metadata: FsMetadata {
                                is_file: false,
                                is_dir: true,
                                len: 0,
                                modified: Some(*modified),
                            },
                        }),
                    }
                }
            }
        }
        Ok(out)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        let norm = Self::normalize(path);
        match inner.nodes.get(&norm) {
            Some(VNode::File { data, .. }) => Ok(data.clone()),
            Some(VNode::Dir { .. }) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{} is a directory", norm.display()),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found", norm.display()),
            )),
        }
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let norm = Self::normalize(path);
        self.ensure_parent(&mut inner, &norm)?;

        let now = SystemTime::now();
        inner.nodes.insert(
            norm.clone(),
            VNode::File {
                data: data.to_vec(),
                modified: now,
            },
        );
        if let Some(parent) = norm.parent() {
            let parent_norm = Self::normalize(parent);
            inner
                .children
                .entry(parent_norm.clone())
                .or_default()
                .insert(
                    norm.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    norm.clone(),
                );
            inner.nodes.entry(parent_norm).or_insert(VNode::Dir { modified: now });
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut current = PathBuf::from("/");
        for comp in path.components() {
            if let Component::Normal(c) = comp {
                current.push(c);
                inner.nodes.entry(current.clone()).or_insert(VNode::Dir {
                    modified: SystemTime::now(),
                });
                if let Some(parent) = current.parent() {
                    let parent_norm = Self::normalize(parent);
                    inner
                        .children
                        .entry(parent_norm.clone())
                        .or_default()
                        .insert(c.to_string_lossy().to_string(), current.clone());
                    inner.nodes.entry(parent_norm).or_insert(VNode::Dir {
                        modified: SystemTime::now(),
                    });
                }
            }
        }
        Ok(())
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn Read + Send>> {
        let data = self.read(path)?;
        Ok(Box::new(std::io::Cursor::new(data)))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let from_norm = Self::normalize(from);
        let to_norm = Self::normalize(to);

        if from_norm == to_norm {
            return Ok(());
        }

        self.ensure_parent(&mut inner, &to_norm)?;

        let node = inner.nodes.remove(&from_norm).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found", from_norm.display()),
            )
        })?;
        inner.nodes.insert(to_norm.clone(), node);

        if let Some(parent) = from_norm.parent() {
            if let Some(children) = inner.children.get_mut(&Self::normalize(parent)) {
                children.retain(|_, p| p != &from_norm);
            }
        }
        if let Some(parent) = to_norm.parent() {
            let parent_norm = Self::normalize(parent);
            let name = to_norm
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            inner
                .children
                .entry(parent_norm)
                .or_default()
                .insert(name, to_norm);
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let norm = Self::normalize(path);
        match inner.nodes.get(&norm) {
            Some(VNode::File { .. }) => {}
            Some(VNode::Dir { .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} is a directory", norm.display()),
                ))
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} not found", norm.display()),
                ))
            }
        }
        inner.nodes.remove(&norm);
        if let Some(parent) = norm.parent() {
            if let Some(children) = inner.children.get_mut(&Self::normalize(parent)) {
                children.retain(|_, p| p != &norm);
            }
        }
        Ok(())
    }
}
