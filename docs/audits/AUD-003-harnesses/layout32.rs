//! The same Rust allocation-layout predicate as WorkArea; this never allocates the work area.
#[no_mangle]
pub extern "C" fn default_layout_supported() -> u32 {
    std::alloc::Layout::from_size_align(2 * 1024 * 1024 * 1024, 16).is_ok() as u32
}
