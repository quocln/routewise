fn main() {
    // The helper is bundled from `resources/helper/`, which
    // `make stage-desktop-helper` fills. A plain cargo build has nothing
    // staged: an empty folder keeps the bundle config valid, and the app then
    // reports the helper as not bundled instead of installing a stale one.
    std::fs::create_dir_all("resources/helper").expect("create resources/helper");
    tauri_build::build()
}
