fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let search_dir = match profile.as_ref() {
        "debug" => "../build/dbg/lib",
        _ => "../build/rel/lib",
    };

    println!("cargo:rustc-link-lib=vfio-user");
    println!("cargo:rustc-link-search={}", search_dir);
}
