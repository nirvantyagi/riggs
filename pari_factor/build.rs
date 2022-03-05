use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR env variable is not set");
    let out_dir = Path::new(&out_dir);
    let out_dir = fs::canonicalize(out_dir).expect("canonicalize OUT_DIR");
    println!("Out dir: {}", out_dir.to_string_lossy());

    let pari_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env variable is not set");
    let pari_dir = Path::new(&pari_dir);
    let pari_dir = pari_dir.join("depend/pari");
    let pari_mirror = out_dir.join("pari-mirror");
    let pari_install = out_dir.join("pari-install");

    println!(
        "cargo:rerun-if-changed={}/CHANGES",
        pari_dir.to_string_lossy()
    );

    // Create a copy of pari directory inside of OUT_DIR
    {
        if pari_mirror.exists() {
            fs::remove_dir_all(&pari_mirror).expect("remove mirror copy of pari");
        }

        let opts = fs_extra::dir::CopyOptions {
            copy_inside: true,
            ..Default::default()
        };
        fs_extra::dir::copy(&pari_dir, &pari_mirror, &opts)
            .expect("create a copy of pari directory to OUT_DIR");
    }

    {
        let output = Command::new(pari_mirror.join("Configure"))
            .arg(OsString::from_iter([
                OsStr::new("--prefix="),
                pari_install.as_os_str(),
            ]))
            .current_dir(&pari_mirror)
            .output()
            .expect("run Configure");

        if !output.status.success() {
            std::io::stderr()
                .write_all(&output.stderr)
                .expect("write error to stderr");
            panic!("./Configure returned non-zero code");
        }
    }

    {
        let output = Command::new("make")
            .arg("install-nodata")
            .current_dir(&pari_mirror)
            .output()
            .expect("run `make install-nodata`");

        if !output.status.success() {
            std::io::stderr()
                .write_all(&output.stderr)
                .expect("write error to stderr");
            panic!("`make install-nodata` returned non-zero code");
        }
    }

    {
        let output = Command::new("make")
            .arg("install-lib-sta")
            .current_dir(&pari_mirror)
            .output()
            .expect("run `make install-lib-sta`");

        if !output.status.success() {
            std::io::stderr()
                .write_all(&output.stderr)
                .expect("write error to stderr");
            panic!("`make install-lib-sta` returned non-zero code");
        }
    }

    let ignored_macros = IgnoreMacros(
        vec![
            "FP_INFINITE".into(),
            "FP_NAN".into(),
            "FP_NORMAL".into(),
            "FP_SUBNORMAL".into(),
            "FP_ZERO".into(),
            "IPPORT_RESERVED".into(),
        ]
        .into_iter()
        .collect(),
    );

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(pari_install.join("include/pari/pari.h").to_string_lossy())
        .allowlist_type("GEN")
        .allowlist_function("GENtostr")
        .allowlist_function("pari_init")
        .allowlist_function("mkintn")
        .allowlist_function("gneg")
        .allowlist_function("gadd")
        .allowlist_function("shifti")
        .allowlist_function("factorint")
        .allowlist_function("compo")
        .parse_callbacks(Box::new(ignored_macros))
        // Finish the builder and generate the bindings.
        .generate()
        .expect("couldn't generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("couldn't write bindings");

    println!(
        "cargo:rustc-link-search=native={}/lib",
        pari_install.to_string_lossy()
    );
    println!("cargo:rustc-link-lib=static=pari");
    println!("cargo:rustc-link-lib=dylib=pari");

    Ok(())
}

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}
