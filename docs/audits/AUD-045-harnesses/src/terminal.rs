use std::fs::File;
use std::os::fd::FromRawFd;

pub(super) fn open() -> std::io::Result<(File, File)> {
    let (mut master, mut slave) = (-1, -1);
    let size = libc::winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty initializes both descriptors; optional name/termios pointers are null,
    // and the winsize pointer is valid for this call.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two distinct owned file descriptors, adopted exactly once.
    let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    use std::os::fd::AsRawFd;
    // SAFETY: this live master descriptor is made nonblocking for the bounded read loop.
    if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((master, slave))
}

pub(super) fn interrupt(pid: u32) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: pid comes from this probe's live child; SIGINT is the tested user action.
    if unsafe { libc::kill(pid, libc::SIGINT) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
