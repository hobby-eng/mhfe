//! A Linux write interposer that schedules two real writes without changing their bytes.
#[allow(
    unsafe_code,
    reason = "the probe interposes the Unix write ABI and calls its syscall"
)]
mod interpose;
