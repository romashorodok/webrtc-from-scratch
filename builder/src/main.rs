use notify_debouncer_full::{
    new_debouncer,
    notify::{RecursiveMode, Watcher},
};
use std::{
    collections::HashSet,
    env,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::channel,
    thread,
    time::Duration,
};

fn find_workspace_root(mut current_dir: PathBuf) -> Option<PathBuf> {
    loop {
        if current_dir.join("Cargo.toml").exists() {
            let content = std::fs::read_to_string(current_dir.join("Cargo.toml")).ok()?;
            if content.contains("[workspace]") {
                return Some(current_dir);
            }
        }

        if !current_dir.pop() {
            return None;
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ProjectInfo {
    path: PathBuf,
    has_cargo: bool,
}

fn find_nearest_pyproject(file_path: &Path) -> Option<ProjectInfo> {
    let mut current = file_path.canonicalize().ok()?;

    loop {
        let pyproject = current.join("pyproject.toml");
        let cargo = current.join("Cargo.toml");

        if pyproject.exists() {
            return Some(ProjectInfo {
                path: current.clone(),
                has_cargo: cargo.exists(),
            });
        }

        if !current.pop() {
            break;
        }
    }

    None
}

fn run_maturin(root: &Path, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("uv");

    let cargo = path.join("Cargo.toml");

    cmd.arg("run")
        .arg("maturin")
        .arg("develop")
        .arg("--skip-install")
        .arg("--bindings=pyo3")
        .arg("--manifest-path")
        .arg(cargo)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let out_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            println!("maturin | {}", line.unwrap());
        }
    });

    let err_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            eprintln!("maturin | {}", line.unwrap());
        }
    });

    let status = child.wait()?;
    println!("Build finished with status: {}", status);

    out_handle.join().unwrap();
    err_handle.join().unwrap();

    Ok(())
}

fn should_ignore(path: &Path) -> bool {
    let ignored_dirs = ["target", "__pycache__"];
    let ignored_exts = ["so", "dll"];

    if path.ancestors().any(|ancestor| {
        ancestor.file_name().map_or(false, |name| {
            ignored_dirs.contains(&name.to_string_lossy().as_ref())
        })
    }) {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if ignored_exts.contains(&ext) {
            return true;
        }
    }

    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root_crate_path =
        find_workspace_root(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)).unwrap();

    let src_path = root_crate_path.join("packages");

    println!("Watching: {:?}", src_path);

    let (tx, rx) = channel();
    let mut debouncer = new_debouncer(Duration::from_secs(1), None, tx)?;
    debouncer
        .watcher()
        .watch(&src_path, RecursiveMode::Recursive)?;

    for result in rx {
        match result {
            Ok(events) => {
                let mut seen = HashSet::new();

                for event in events {
                    for path in &event.paths {
                        if should_ignore(path) {
                            continue;
                        }

                        if let Some(info) = find_nearest_pyproject(path) {
                            if info.has_cargo && seen.insert(info.clone()) {
                                println!("Change detected in: {:?}", info.path);
                                if let Err(e) = run_maturin(&root_crate_path, &info.path) {
                                    eprintln!("Error building {}: {:?}", info.path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
            Err(errors) => {
                for error in errors {
                    eprintln!("Watch error: {:?}", error);
                }
            }
        }
    }

    Ok(())
}
