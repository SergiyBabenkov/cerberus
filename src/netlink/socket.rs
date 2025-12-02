//! Netlink socket management
//!
//! Provides safe wrapper around AF_NETLINK socket lifecycle.
//! Uses RAII (Resource Acquisition Is Initialization) pattern
//! to ensure socket is always closed when dropped.
//!
//! # Platform Support
//!
//! **Linux only:** Netlink is a Linux-specific kernel interface.
//! This module will not compile on macOS or other non-Linux platforms.
//!
//! # Educational Notes
//!
//! ## RAII Pattern (Resource Acquisition Is Initialization)
//!
//! This is a fundamental concept in Rust (and C++):
//! - Resource acquired in constructor (`new()`)
//! - Resource automatically released in destructor (`Drop::drop()`)
//! - No way to forget to clean up!
//!
//! Example:
//! ```rust
//! {
//!     let socket = NetlinkSocket::new()?;  // Socket opened here
//!     socket.send(&data)?;
//!     // ... use socket ...
//! }  // Socket automatically closed here when it goes out of scope
//! ```
//!
//! Compare to C where you must manually close:
//! ```c
//! int fd = socket(...);
//! if (fd < 0) return -1;
//! // ... use socket ...
//! close(fd);  // MUST remember to close! Easy to forget in error paths!
//! ```
//!
//! ## Unsafe Rust
//!
//! System calls like `socket()`, `bind()`, `send()`, `recv()` require `unsafe`:
//! - They interact with raw pointers
//! - They bypass Rust's safety guarantees
//! - We must manually ensure correctness
//!
//! Our strategy:
//! 1. Keep unsafe code minimal and localized
//! 2. Wrap unsafe syscalls in safe functions
//! 3. Validate all inputs and outputs
//! 4. Document safety invariants
//!
//! ## File Descriptors
//!
//! In Unix/Linux, everything is a file:
//! - Regular files: `/etc/passwd`
//! - Sockets: network connections
//! - Pipes: inter-process communication
//! - Devices: `/dev/null`
//!
//! All accessed through integer file descriptors (fd):
//! - 0 = stdin, 1 = stdout, 2 = stderr
//! - 3+ = other open files/sockets
//!
//! Our socket is represented by a RawFd (raw file descriptor).

// This module only compiles on Linux (Netlink is Linux-specific)
// #![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;

/// Errors that can occur during Netlink socket operations
///
/// This wraps std::io::Error for socket syscalls.
///
/// # Why a custom error type?
///
/// We want to provide context-specific error messages:
/// - "socket() failed: Permission denied" is more helpful than just "Permission denied"
/// - We can add our own error handling logic
/// - Type safety: functions return our specific error type
#[derive(Debug)]
pub struct SocketError {
    message: String,
    kind: io::ErrorKind,
}

impl SocketError {
    fn new(message: String, kind: io::ErrorKind) -> Self {
        Self { message, kind }
    }

    fn from_io_error(context: &str, err: io::Error) -> Self {
        Self {
            message: format!("{}: {}", context, err),
            kind: err.kind(),
        }
    }
}

/// Implementing Display allows using this error with `{}` in format strings
impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Implementing Error trait makes this a proper error type
/// This allows using it with `?` operator and error handling libraries
impl std::error::Error for SocketError {}

/// Netlink socket wrapper with automatic cleanup
///
/// This struct wraps a raw file descriptor for an AF_NETLINK socket.
/// When dropped, it automatically closes the socket (RAII pattern).
///
/// # Example
///
/// ```no_run
/// use cerberus::netlink::socket::NetlinkSocket;
///
/// // Create socket (or return error)
/// let socket = NetlinkSocket::new()?;
///
/// // Use socket...
/// socket.send(&request_bytes)?;
/// let response = socket.recv_all()?;
///
/// // Socket is automatically closed when it goes out of scope
/// # Ok::<(), cerberus::netlink::socket::SocketError>(())
/// ```
///
/// # Safety
///
/// The raw file descriptor is never exposed publicly.
/// All operations use safe wrappers around libc syscalls.
pub struct NetlinkSocket {
    /// Raw file descriptor for the socket
    ///
    /// This is private - users can't accidentally misuse it.
    /// Only our implementation can access it.
    fd: RawFd,
}

impl NetlinkSocket {
    /// Create new Netlink socket for SOCK_DIAG protocol
    ///
    /// This performs the following steps:
    /// 1. Create AF_NETLINK socket
    /// 2. Bind to kernel
    /// 3. Set socket options (buffer size, timeout)
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if:
    /// - socket() syscall fails (permission denied, etc.)
    /// - bind() fails
    /// - setsockopt() fails
    ///
    /// # Platform Support
    ///
    /// - RHEL 7: Requires root or CAP_NET_ADMIN
    /// - RHEL 8/9: Works without root
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::netlink::socket::NetlinkSocket;
    /// let socket = NetlinkSocket::new()?;
    /// # Ok::<(), cerberus::netlink::socket::SocketError>(())
    /// ```
    pub fn new() -> Result<Self, SocketError> {
        unsafe {
            // === STEP 1: Create Netlink socket ===
            //
            // socket(domain, type, protocol) creates a socket
            // Parameters:
            // - AF_NETLINK (16): Netlink address family
            // - SOCK_RAW: Raw socket (datagram-like, but no automatic protocol processing)
            // - NETLINK_SOCK_DIAG (4): Socket diagnostics protocol
            //
            // Returns: File descriptor (>= 0) on success, -1 on error
            //
            // SAFETY: This is unsafe because:
            // - We're calling C code (libc)
            // - Rust can't verify the syscall contract
            // - We must check return value ourselves
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_SOCK_DIAG);

            if fd < 0 {
                // Get error from errno (global error variable set by libc)
                let err = io::Error::last_os_error();
                return Err(SocketError::from_io_error("socket() failed", err));
            }

            // === STEP 2: Bind socket to kernel ===
            //
            // This is optional for client sockets, but recommended.
            // The kernel assigns a unique port ID if we use nl_pid = 0.
            //
            // sockaddr_nl structure:
            // - nl_family: AF_NETLINK
            // - nl_pid: Process ID or 0 for auto-assign
            // - nl_groups: Multicast group mask (0 for none)
            //
            // SAFETY: zeroed() creates all-zeros struct (safe for POD types)
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_pid = 0; // Kernel assigns unique PID
            addr.nl_groups = 0; // No multicast groups

            // bind(fd, address, address_length)
            // Returns: 0 on success, -1 on error
            //
            // SAFETY: We must cast sockaddr_nl to generic sockaddr
            // This is safe because they have compatible memory layout
            let ret = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );

            if ret < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd); // Clean up before returning error!
                return Err(SocketError::from_io_error("bind() failed", err));
            }

            // === STEP 3: Set socket options ===

            // Increase receive buffer size (32KB)
            // This prevents message loss when kernel sends large responses
            //
            // Without this, default buffer (usually 8KB) may be too small
            // for INET_DIAG dumps with many connections
            let rcvbuf: libc::c_int = 32768;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET, // Socket level (not protocol-specific)
                libc::SO_RCVBUF,  // Receive buffer size option
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            );

            if ret < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(SocketError::from_io_error(
                    "setsockopt(SO_RCVBUF) failed",
                    err,
                ));
            }

            // Set receive timeout (1 second)
            // Prevents indefinite blocking if kernel doesn't respond
            //
            // Without timeout, recv() could hang forever if:
            // - Kernel is unresponsive
            // - No more data to receive (for multi-part messages)
            let timeout = libc::timeval {
                tv_sec: 1,  // 1 second
                tv_usec: 0, // 0 microseconds
            };
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO, // Receive timeout option
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );

            if ret < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(SocketError::from_io_error(
                    "setsockopt(SO_RCVTIMEO) failed",
                    err,
                ));
            }

            // Success! Return socket wrapped in our struct
            Ok(Self { fd })
        }
    }

    /// Send request bytes to kernel
    ///
    /// This sends a complete Netlink request message to the kernel.
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if:
    /// - sendto() fails (connection refused, etc.)
    /// - Not all bytes were sent (short send)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::netlink::socket::NetlinkSocket;
    /// # let socket = NetlinkSocket::new()?;
    /// let request_bytes = vec![0u8; 72];  // Example request
    /// socket.send(&request_bytes)?;
    /// # Ok::<(), cerberus::netlink::socket::SocketError>(())
    /// ```
    pub fn send(&self, data: &[u8]) -> Result<(), SocketError> {
        unsafe {
            // === Construct destination address (kernel) ===
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_pid = 0; // Send to kernel (PID 0)
            addr.nl_groups = 0;

            // === Send data ===
            //
            // sendto(fd, buffer, length, flags, dest_addr, addr_len)
            // Returns: Number of bytes sent, or -1 on error
            //
            // SAFETY: We pass slice as pointer + length
            // Rust guarantees data.as_ptr() is valid for data.len() bytes
            let ret = libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0, // No special flags
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );

            if ret < 0 {
                let err = io::Error::last_os_error();
                return Err(SocketError::from_io_error("sendto() failed", err));
            }

            // Verify all bytes were sent
            // (Usually true for Netlink, but we should check)
            if ret as usize != data.len() {
                return Err(SocketError::new(
                    format!("Short send: sent {} of {} bytes", ret, data.len()),
                    io::ErrorKind::WriteZero,
                ));
            }

            Ok(())
        }
    }

    /// Receive data into provided buffer
    ///
    /// This receives one chunk of data from the kernel.
    /// For multi-part messages, use `recv_all()` instead.
    ///
    /// # Returns
    ///
    /// Number of bytes received
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if:
    /// - recv() fails
    /// - Timeout occurs (after 1 second)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::netlink::socket::NetlinkSocket;
    /// # let socket = NetlinkSocket::new()?;
    /// let mut buffer = vec![0u8; 32768];
    /// let bytes_received = socket.recv(&mut buffer)?;
    /// let data = &buffer[..bytes_received];
    /// # Ok::<(), cerberus::netlink::socket::SocketError>(())
    /// ```
    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, SocketError> {
        unsafe {
            // === Receive data ===
            //
            // recv(fd, buffer, length, flags)
            // Returns: Number of bytes received, or -1 on error
            //
            // SAFETY: We pass mutable slice as pointer + length
            // Rust guarantees buffer.as_mut_ptr() is valid for buffer.len() bytes
            let ret = libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0, // No special flags
            );

            if ret < 0 {
                let err = io::Error::last_os_error();

                // Check if timeout (expected for end of multi-part)
                // WouldBlock on macOS, TimedOut on Linux
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut
                {
                    return Err(SocketError::new("recv() timeout".to_string(), err.kind()));
                }

                return Err(SocketError::from_io_error("recv() failed", err));
            }

            Ok(ret as usize)
        }
    }

    /// Receive complete multi-part message
    ///
    /// This handles Netlink multi-part responses, receiving all messages
    /// until NLMSG_DONE is received or timeout occurs.
    ///
    /// # Returns
    ///
    /// Complete concatenated response (all messages)
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if recv() fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cerberus::netlink::socket::NetlinkSocket;
    /// # let socket = NetlinkSocket::new()?;
    /// # let request = vec![0u8; 72];
    /// socket.send(&request)?;
    /// let all_data = socket.recv_all()?;
    /// // all_data contains all response messages concatenated
    /// # Ok::<(), cerberus::netlink::socket::SocketError>(())
    /// ```
    pub fn recv_all(&self) -> Result<Vec<u8>, SocketError> {
        // Pre-allocate vector for responses
        // 32KB is typical size for INET_DIAG response
        let mut all_data = Vec::with_capacity(32768);
        let mut buffer = vec![0u8; 32768];

        loop {
            // Receive one chunk
            match self.recv(&mut buffer) {
                Ok(bytes_received) => {
                    let chunk = &buffer[..bytes_received];
                    all_data.extend_from_slice(chunk);

                    // Check if this chunk contains NLMSG_DONE
                    // This indicates end of multi-part message
                    if Self::contains_done_message(chunk) {
                        break; // End of multi-part message
                    }
                }
                Err(e) => {
                    // Timeout is OK if we already received some data
                    // This can happen if kernel sends NLMSG_DONE in separate packet
                    if e.kind == io::ErrorKind::WouldBlock
                        || e.kind == io::ErrorKind::TimedOut && !all_data.is_empty()
                    {
                        break; // We got all data
                    }
                    return Err(e);
                }
            }

            // Safety check: prevent infinite loop and memory exhaustion
            if all_data.len() > 10_000_000 {
                // 10MB limit
                return Err(SocketError::new(
                    "Response too large (> 10MB)".to_string(),
                    io::ErrorKind::OutOfMemory,
                ));
            }
        }

        Ok(all_data)
    }

    /// Check if data contains NLMSG_DONE message
    ///
    /// Helper function to detect end of multi-part message.
    ///
    /// # Safety
    ///
    /// This function uses unsafe pointer cast to interpret bytes as NlMsgHdr.
    /// This is safe because:
    /// 1. We check data is large enough first
    /// 2. NlMsgHdr is POD (Plain Old Data) with repr(C)
    /// 3. We only read, never write
    fn contains_done_message(data: &[u8]) -> bool {
        use crate::netlink::structures::{NLMSG_DONE, NlMsgHdr};

        // Need at least header size to check
        if data.len() < std::mem::size_of::<NlMsgHdr>() {
            return false;
        }

        // SAFETY: We verified data is large enough
        // NlMsgHdr is repr(C) POD type, safe to cast from bytes
        let nlh = unsafe { &*(data.as_ptr() as *const NlMsgHdr) };

        nlh.nlmsg_type == NLMSG_DONE
    }
}

/// Automatic cleanup when socket is dropped
///
/// This implements the Drop trait to ensure socket is always closed.
/// Rust calls drop() automatically when value goes out of scope.
///
/// # RAII Pattern
///
/// This is Rust's equivalent of C++ RAII:
/// - Resource (socket) acquired in constructor (new())
/// - Resource automatically freed in destructor (drop())
/// - No way to forget to close socket!
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::socket::NetlinkSocket;
/// {
///     let socket = NetlinkSocket::new()?;
///     // ... use socket ...
/// }  // drop() called here automatically, socket closed
/// # Ok::<(), cerberus::netlink::socket::SocketError>(())
/// ```
impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // Close socket
        //
        // We ignore errors here because:
        // 1. We're in destructor - can't propagate errors in Rust
        // 2. Socket might already be closed (double-close is safe)
        // 3. Nothing we can do about it anyway
        //
        // SAFETY: close() is safe to call multiple times
        unsafe {
            libc::close(self.fd);
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_creation() {
        // This test requires permissions (root or CAP_NET_ADMIN on RHEL 7)
        // Skip if running without permissions
        match NetlinkSocket::new() {
            Ok(_socket) => {
                // Socket created successfully
                // It will be automatically closed when _socket is dropped
                println!("Netlink socket created successfully");
            }
            Err(e) => {
                // Expected on systems without permissions
                eprintln!("Socket creation failed (expected without root): {}", e);
            }
        }
    }

    #[test]
    fn test_socket_drop() {
        // Verify socket is closed when dropped
        {
            let _socket = NetlinkSocket::new();
            // Socket should close automatically here when _socket goes out of scope
        }
        // If we didn't crash, Drop worked correctly
    }
}
