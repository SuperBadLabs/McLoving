//! Symlink-safe reclamation of controller-acknowledged workspace evidence.

use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::{ExecutionError, WorkspaceRootGuard, is_link_or_reparse_point, sync_directories};
use crate::validate_relative_path;

const AGENT_RESULT_DIRECTORY: &str = ".agent-results";

/// Removes one normalized path below the workspace root without following a
/// workload-created symlink or reparse point.
///
/// Callers must first obtain durable controller acknowledgement for every
/// spool referenced below this path. Missing paths are accepted so cleanup is
/// safely repeatable after a crash.
pub async fn remove_terminal_relative_path(
    workspace_root: &Path,
    relative_path: &Path,
) -> Result<Vec<PathBuf>, ExecutionError> {
    validate_relative_path(relative_path)?;
    let root_metadata = match tokio::fs::symlink_metadata(workspace_root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !root_metadata.is_dir() || is_link_or_reparse_point(&root_metadata) {
        return Err(ExecutionError::ReplacedWorkspaceRoot);
    }
    restore_directory_access(workspace_root, &root_metadata).await?;
    let workspace_root_guard = WorkspaceRootGuard::open(workspace_root)?;
    workspace_root_guard.ensure_original(workspace_root)?;

    let path = workspace_root.join(relative_path);
    let mut changed = Vec::new();
    let mut current = workspace_root.to_owned();
    let mut components = relative_path.components().peekable();
    while let Some(component) = components.next() {
        workspace_root_guard.ensure_original(workspace_root)?;
        let Component::Normal(component) = component else {
            unreachable!("terminal path was validated above");
        };
        current.push(component);
        let is_leaf = components.peek().is_none();
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata)
                if !is_leaf && metadata.is_dir() && !is_link_or_reparse_point(&metadata) =>
            {
                restore_directory_access(&current, &metadata).await?;
            }
            Ok(metadata) if !is_leaf => {
                remove_terminal_replacement_entry(&current, &metadata).await?;
                changed.push(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent")
                        .to_owned(),
                );
                break;
            }
            Ok(metadata) if metadata.is_dir() && !is_link_or_reparse_point(&metadata) => {
                remove_directory_tree_no_follow(&current).await?;
                changed.push(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent")
                        .to_owned(),
                );
                break;
            }
            Ok(metadata) => {
                remove_terminal_replacement_entry(&current, &metadata).await?;
                changed.push(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent")
                        .to_owned(),
                );
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    workspace_root_guard.ensure_original(workspace_root)?;
    // Keep bounded per-organization anchors so successive attempts extend
    // durable directory entries instead of recreating and re-flushing the
    // whole chain from the workspace root.
    let mut anchor = workspace_root.to_owned();
    let mut components = relative_path.components();
    if let Some(Component::Normal(first)) = components.next() {
        anchor.push(first);
        if first == AGENT_RESULT_DIRECTORY
            && let Some(Component::Normal(organization)) = components.next()
        {
            anchor.push(organization);
        }
    }
    changed.extend(
        prune_empty_directories(
            workspace_root,
            &workspace_root_guard,
            &anchor,
            path.parent(),
        )
        .await?,
    );
    Ok(changed)
}

/// Flushes a completed attempt cleanup as one durability barrier before its
/// journal descriptors retire. Anchors are included even when a replay finds
/// the paths already absent; a missing boundary falls back to its nearest
/// surviving ancestor so an interrupted predecessor's removal is not lost.
pub async fn flush_terminal_cleanup(
    workspace_root: &Path,
    workspace: &Path,
    mut changed: Vec<PathBuf>,
) -> Result<(), ExecutionError> {
    validate_relative_path(workspace)?;
    let Some(Component::Normal(organization)) = workspace.components().next() else {
        return Err(ExecutionError::InvalidWorkspace(
            crate::JournalError::InvalidRelativePath,
        ));
    };
    changed.push(workspace_root.join(organization));
    changed.push(
        workspace_root
            .join(AGENT_RESULT_DIRECTORY)
            .join(organization),
    );
    changed.sort();
    changed.dedup();
    let flush_root = workspace_root.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut boundaries = Vec::with_capacity(changed.len());
        for directory in changed {
            let mut candidate = directory.as_path();
            loop {
                if candidate.is_dir() {
                    boundaries.push(candidate.to_owned());
                    break;
                }
                if candidate == flush_root {
                    break;
                }
                match candidate.parent() {
                    Some(parent) if parent.starts_with(&flush_root) => candidate = parent,
                    _ => break,
                }
            }
        }
        boundaries.sort();
        boundaries.dedup();
        sync_directories(&boundaries)
    })
    .await
    .map_err(|error| {
        std::io::Error::other(format!("terminal cleanup durability task failed: {error}"))
    })??;
    Ok(())
}

async fn remove_terminal_replacement_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        if windows_entry_is_directory(metadata) {
            tokio::fs::remove_dir(path).await
        } else {
            if !is_link_or_reparse_point(metadata) {
                restore_file_deletion_access(path, metadata).await?;
            }
            tokio::fs::remove_file(path).await
        }
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        tokio::fs::remove_file(path).await
    }
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
async fn restore_file_deletion_access(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    if metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        tokio::fs::set_permissions(path, permissions).await?;
    }
    Ok(())
}

async fn restore_directory_access(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        tokio::fs::set_permissions(path, permissions).await
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
        Ok(())
    }
}

async fn remove_directory_tree_no_follow(path: &Path) -> Result<(), std::io::Error> {
    let root = path.to_owned();
    tokio::task::spawn_blocking(move || remove_directory_tree_no_follow_sync(&root))
        .await
        .map_err(|error| std::io::Error::other(format!("workspace cleanup task failed: {error}")))?
}

fn remove_directory_tree_no_follow_sync(root: &Path) -> Result<(), std::io::Error> {
    let mut stack = vec![(root.to_owned(), false)];
    while let Some((path, expanded)) = stack.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if is_link_or_reparse_point(&metadata) {
            remove_terminal_replacement_entry_sync(&path, &metadata)?;
            continue;
        }
        if !metadata.is_dir() {
            restore_file_deletion_access_sync(&path, &metadata)?;
            std::fs::remove_file(&path)?;
            continue;
        }
        if expanded {
            std::fs::remove_dir(&path)?;
            continue;
        }

        restore_directory_access_sync(&path, &metadata)?;
        stack.push((path.clone(), true));
        for entry in std::fs::read_dir(&path)? {
            stack.push((entry?.path(), false));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn restore_file_deletion_access_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    if metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn restore_file_deletion_access_sync(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    Ok(())
}

fn restore_directory_access_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(path, permissions)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
        Ok(())
    }
}

fn remove_terminal_replacement_entry_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        if windows_entry_is_directory(metadata) {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        std::fs::remove_file(path)
    }
}

#[cfg(windows)]
fn windows_entry_is_directory(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0
}

async fn prune_empty_directories(
    workspace_root: &Path,
    workspace_root_guard: &WorkspaceRootGuard,
    anchor: &Path,
    start: Option<&Path>,
) -> Result<Option<PathBuf>, ExecutionError> {
    let mut removed_any = false;
    let mut current = start.map(Path::to_owned);
    while let Some(directory) = current {
        workspace_root_guard.ensure_original(workspace_root)?;
        if directory == workspace_root || directory == anchor {
            return Ok(removed_any.then(|| directory.clone()));
        }
        if !directory.starts_with(workspace_root) {
            return Err(ExecutionError::InvalidWorkspace(
                crate::JournalError::InvalidRelativePath,
            ));
        }
        let parent = directory.parent().map(Path::to_owned);
        match tokio::fs::remove_dir(&directory).await {
            Ok(()) => {
                removed_any = true;
                current = parent;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => current = parent,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(removed_any.then(|| directory.clone()));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}
