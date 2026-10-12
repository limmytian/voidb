fn main() {
    println!(
        "cargo:rustc-env=VOIDB_BUILD_TARGET={}",
        std::env::var("TARGET").expect("Cargo target")
    );
}
