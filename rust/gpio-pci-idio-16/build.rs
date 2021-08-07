fn main() {
   println!("cargo:rustc-link-lib=vfio-user");
   println!("cargo:rustc-link-search=../build/dbg/lib");
}
