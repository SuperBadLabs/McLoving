use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=MCLOVING_BUILD_SOURCE_HEAD");
    println!("cargo:rerun-if-env-changed=MCLOVING_BUILD_SOURCE_TREE");
    let head = env::var("MCLOVING_BUILD_SOURCE_HEAD").unwrap_or_else(|_| "unbound".to_owned());
    let tree = env::var("MCLOVING_BUILD_SOURCE_TREE").unwrap_or_else(|_| "unbound".to_owned());
    println!("cargo:rustc-env=MCLOVING_BUILD_SOURCE_HEAD={head}");
    println!("cargo:rustc-env=MCLOVING_BUILD_SOURCE_TREE={tree}");
}
