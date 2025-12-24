//! Build script for Windows resource embedding (icon, manifest)
//! 
//! This script properly handles cross-compilation by checking the TARGET
//! environment variable at runtime rather than using compile-time cfg.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    
    // Only embed Windows resources when targeting Windows
    if target.contains("windows") {
        embed_windows_resources();
    }
    
    // Rerun if assets change
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/app.manifest");
}

#[cfg(feature = "_windows_build")]
fn embed_windows_resources() {
    // This function is never called - just for IDE support
    unimplemented!()
}

#[cfg(not(feature = "_windows_build"))]
fn embed_windows_resources() {
    use std::path::Path;
    
    // Check if winresource is available (it should be via build-dependencies)
    let icon_path = Path::new("assets/icon.ico");
    let manifest_path = Path::new("assets/app.manifest");
    
    if !icon_path.exists() {
        println!("cargo:warning=Windows icon not found at assets/icon.ico");
        println!("cargo:warning=The executable will not have an icon.");
        return;
    }
    
    let mut res = winresource::WindowsResource::new();
    
    // Set the application icon
    res.set_icon("assets/icon.ico");
    
    // Set version information
    res.set("ProductName", "Hash Tools");
    res.set("FileDescription", "Modern File Hash Calculator with SM3 Support");
    res.set("LegalCopyright", "MIT License");
    res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
    res.set("FileVersion", env!("CARGO_PKG_VERSION"));
    
    // Set manifest if it exists
    if manifest_path.exists() {
        res.set_manifest_file("assets/app.manifest");
    }
    
    // Compile resources
    if let Err(e) = res.compile() {
        println!("cargo:warning=Failed to compile Windows resources: {}", e);
    }
}
