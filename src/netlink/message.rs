//! Netlink message construction and parsing
//!
//! This module handles building INET_DIAG request messages and
//! parsing multi-part response messages from the kernel.
//!
//! # Educational Notes
//!
//! ## Netlink Protocol Basics
//!
//! Netlink is a Linux kernel interface for communication between kernel and user space.
//! Unlike traditional system calls that use function arguments, Netlink uses messages:
//!
//! 1. **User space** builds a message (header + payload)
//! 2. **Kernel** receives message, processes it
//! 3. **Kernel** sends back response message(s)
//!
//! ## Message Format
//!
//! All Netlink messages have this structure:
//! ```text
//! ┌─────────────────────────────┐
//! │ NlMsgHdr (16 bytes)         │  ← Netlink header (metadata)
//! ├─────────────────────────────┤
//! │ Payload (variable bytes)    │  ← Protocol-specific data
//! ├─────────────────────────────┤
//! │ Padding (0-3 bytes)         │  ← Align to 4-byte boundary
//! └─────────────────────────────┘
//! ```
//!
//! ## Why 4-byte Alignment?
//!
//! CPUs work most efficiently when data is aligned to "natural boundaries":
//! - x86 CPUs read memory in chunks (4 bytes, 8 bytes, 16 bytes)
//! - Unaligned reads may require 2 memory accesses instead of 1
//! - Netlink enforces 4-byte alignment to ensure efficient parsing
//!
//! Example: Message of 73 bytes → pad to 76 bytes (next multiple of 4)
//!
//! ## Multi-part Messages
//!
//! Kernel can send multiple responses in sequence:
//! ```text
//! [ Message 1 ] [ Message 2 ] [ Message 3 ] [ NLMSG_DONE ]
//! ```
//!
//! We must parse each message until we see NLMSG_DONE.
//!
//! ## Unsafe Code in This Module
//!
//! This module uses `unsafe` for binary protocol parsing:
//! - Casting byte slices to C structures (`repr(C)`)
//! - This is safe ONLY if:
//!   1. Buffer is large enough (we check!)
//!   2. Alignment is correct (Netlink guarantees 4-byte alignment)
//!   3. Structure has no invalid bit patterns (our structs are POD types)
//!
//! We minimize unsafe code and document all safety invariants.

// #![cfg(target_os = "linux")]

use crate::netlink::structures::*;
use std::collections::HashMap;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors that can occur during message operations
///
/// This wraps error messages for message construction and parsing failures.
///
/// # Why a Custom Error Type?
///
/// - Provides context-specific error messages
/// - Allows adding error handling logic later
/// - Type safety: functions clearly declare they can fail
#[derive(Debug)]
pub struct MessageError {
    message: String,
}

impl MessageError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

/// Implementing Display allows using this error with `{}` in format strings
impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Implementing Error trait makes this a proper error type
/// This allows using it with `?` operator and error handling libraries
impl std::error::Error for MessageError {}

// ============================================================================
// MESSAGE CONSTRUCTION
// ============================================================================

/// Build complete INET_DIAG request message
///
/// This constructs a Netlink message containing an INET_DIAG request.
/// The message is ready to send via NetlinkSocket.
///
/// # Message Structure
///
/// ```text
/// ┌─────────────────────────────┐
/// │ NlMsgHdr (16 bytes)         │  ← Netlink header
/// ├─────────────────────────────┤
/// │ InetDiagReqV2 (56 bytes)    │  ← INET_DIAG request
/// ├─────────────────────────────┤
/// │ Padding (0-3 bytes)         │  ← Align to 4-byte boundary
/// └─────────────────────────────┘
/// Total: 72 bytes (aligned)
/// ```
///
/// # Parameters
///
/// * `req` - INET_DIAG request structure (specifies what to query)
/// * `seq` - Sequence number for matching responses (any u32 value)
///
/// # Returns
///
/// Serialized message bytes ready to send via socket
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::structures::*;
/// # use cerberus::netlink::message::build_inet_diag_request;
/// # use std::net::Ipv4Addr;
/// let sock_id = build_exact_socket_id(
///     Ipv4Addr::new(192, 168, 1, 100),
///     8080,
///     Ipv4Addr::new(10, 0, 1, 5),
///     5000,
/// );
///
/// let req = InetDiagReqV2 {
///     sdiag_family: AF_INET,
///     sdiag_protocol: IPPROTO_TCP,
///     idiag_ext: (1 << (INET_DIAG_INFO - 1)),
///     pad: 0,
///     idiag_states: 1 << TCP_ESTABLISHED,
///     id: sock_id,
/// };
///
/// let message = build_inet_diag_request(&req, 12345);
/// // Now send via socket: socket.send(&message)?;
/// ```
pub fn build_inet_diag_request(req: &InetDiagReqV2, seq: u32) -> Vec<u8> {
    // === STEP 1: Calculate sizes ===
    //
    // We need to know how much memory to allocate.
    // The payload is just the InetDiagReqV2 structure.
    let payload_size = std::mem::size_of::<InetDiagReqV2>();

    // Total space needed includes header + payload + padding
    let total_size = nlmsg_space(payload_size);

    // === STEP 2: Allocate buffer ===
    //
    // Vec::with_capacity() pre-allocates space (avoids reallocation)
    // This is more efficient than letting Vec grow dynamically
    let mut buffer = Vec::with_capacity(total_size);

    // === STEP 3: Build Netlink header ===
    //
    // The header contains metadata about the message:
    // - nlmsg_len: Total length (header + payload)
    // - nlmsg_type: What kind of message (SOCK_DIAG_BY_FAMILY)
    // - nlmsg_flags: Request flags (REQUEST + DUMP for multi-part response)
    // - nlmsg_seq: Sequence number (for matching request/response)
    // - nlmsg_pid: Process ID (0 = kernel assigns automatically)
    let nlh = NlMsgHdr {
        nlmsg_len: nlmsg_length(payload_size),
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP, // Request + multi-part response
        nlmsg_seq: seq,
        nlmsg_pid: 0, // Kernel assigns
    };

    // === STEP 4: Serialize header to bytes ===
    //
    // SAFETY: This unsafe block converts a Rust struct to raw bytes.
    //
    // Why is this safe?
    // 1. NlMsgHdr is #[repr(C)] - memory layout matches C (predictable, no padding)
    // 2. NlMsgHdr contains only primitive types (u32, u16) - no pointers or references
    // 3. All bit patterns are valid for these types (no invalid values)
    // 4. We only read the struct, don't modify it
    // 5. The slice lifetime is tied to the struct (borrow checker ensures validity)
    //
    // This is the standard way to serialize binary protocol structures in Rust.
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &nlh as *const _ as *const u8, // Convert struct pointer to byte pointer
            std::mem::size_of::<NlMsgHdr>(), // Size in bytes
        )
    };
    buffer.extend_from_slice(header_bytes);

    // === STEP 5: Serialize request payload ===
    //
    // SAFETY: Same reasoning as header serialization above.
    // InetDiagReqV2 is also #[repr(C)] with only primitive types.
    let payload_bytes = unsafe {
        std::slice::from_raw_parts(
            req as *const _ as *const u8,
            std::mem::size_of::<InetDiagReqV2>(),
        )
    };
    buffer.extend_from_slice(payload_bytes);

    // === STEP 6: Add padding to 4-byte boundary ===
    //
    // Netlink requires all messages to be aligned to 4 bytes.
    // Example: 73 bytes → add 3 bytes of padding → 76 bytes (divisible by 4)
    //
    // Why? CPU efficiency - reading aligned data is faster.
    while buffer.len() % 4 != 0 {
        buffer.push(0); // Add zero byte
    }

    buffer
}

// ============================================================================
// MESSAGE PARSING
// ============================================================================

/// Parsed Netlink message
///
/// Represents one message from a multi-part response.
///
/// # Message Types
///
/// - **InetDiag**: Contains connection information (inet_diag_msg + attributes)
/// - **Done**: End of multi-part message (no more data)
/// - **Error**: Kernel error (contains errno code)
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::message::*;
/// # let response_data = vec![0u8; 100];
/// let messages = parse_netlink_messages(&response_data)?;
///
/// for msg in messages {
///     match msg {
///         ParsedMessage::InetDiag { msg, attributes } => {
///             println!("Connection state: {}", msg.idiag_state);
///             // Process tcp_info from attributes...
///         }
///         ParsedMessage::Done => {
///             println!("End of messages");
///             break;
///         }
///         ParsedMessage::Error(errno) => {
///             eprintln!("Kernel error: {}", errno);
///         }
///     }
/// }
/// # Ok::<(), MessageError>(())
/// ```
#[derive(Debug)]
pub enum ParsedMessage {
    /// inet_diag_msg with optional attributes
    ///
    /// Contains connection info (state, addresses, queues) and
    /// optional attributes like tcp_info, congestion algorithm name, etc.
    InetDiag {
        msg: InetDiagMsg,
        attributes: HashMap<u16, Vec<u8>>,
    },

    /// End of multi-part message
    ///
    /// When you see this, stop processing - no more messages to read.
    Done,

    /// Error message
    ///
    /// Contains errno (positive number):
    /// - ENOENT (2) = Connection not found
    /// - EACCES (13) = Permission denied
    /// - 0 = ACK (not an error, just acknowledgment)
    Error(i32),
}

/// Parse multi-part Netlink response
///
/// Extracts individual messages from concatenated response data.
/// The kernel can send multiple messages in one batch, followed by NLMSG_DONE.
///
/// # Message Flow
///
/// ```text
/// Response data:
/// ┌────────────────┐
/// │ Message 1      │ ← SOCK_DIAG_BY_FAMILY (connection 1)
/// ├────────────────┤
/// │ Message 2      │ ← SOCK_DIAG_BY_FAMILY (connection 2)
/// ├────────────────┤
/// │ ...            │
/// ├────────────────┤
/// │ Message N      │ ← SOCK_DIAG_BY_FAMILY (connection N)
/// ├────────────────┤
/// │ NLMSG_DONE     │ ← End marker
/// └────────────────┘
/// ```
///
/// # Parameters
///
/// * `data` - Raw response bytes from NetlinkSocket::recv_all()
///
/// # Returns
///
/// * `Ok(Vec<ParsedMessage>)` - Successfully parsed messages
/// * `Err(MessageError)` - Parse error (malformed data, truncated, etc.)
///
/// # Errors
///
/// Returns error if:
/// - Message length is invalid (too small, exceeds buffer)
/// - Buffer is truncated (incomplete message)
/// - Structure sizes don't match expected values
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::socket::NetlinkSocket;
/// # use cerberus::netlink::message::parse_netlink_messages;
/// # let socket = NetlinkSocket::new()?;
/// # let request = vec![0u8; 72];
/// socket.send(&request)?;
/// let response_data = socket.recv_all()?;
/// let messages = parse_netlink_messages(&response_data)?;
/// println!("Received {} messages", messages.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_netlink_messages(data: &[u8]) -> Result<Vec<ParsedMessage>, MessageError> {
    let mut messages = Vec::new();
    let mut offset = 0;

    // === ITERATE THROUGH CONCATENATED MESSAGES ===
    //
    // Netlink can send multiple messages concatenated in one buffer.
    // We parse each one until we run out of data or hit NLMSG_DONE.
    while offset + std::mem::size_of::<NlMsgHdr>() <= data.len() {
        // === Parse Netlink header ===
        //
        // SAFETY: This unsafe block casts raw bytes to NlMsgHdr structure.
        //
        // Why is this safe?
        // 1. We verified buffer has at least size_of::<NlMsgHdr>() bytes (check above)
        // 2. Netlink guarantees 4-byte alignment (all messages are aligned)
        // 3. NlMsgHdr is #[repr(C)] POD type (no invalid bit patterns)
        // 4. We only read, never modify
        // 5. We copy the structure immediately (not holding a long-lived reference)
        let nlh = unsafe { &*(data[offset..].as_ptr() as *const NlMsgHdr) };

        let msg_len = nlh.nlmsg_len as usize;

        // === Validate message length ===
        //
        // Protect against malformed messages that could cause:
        // - Buffer overruns (reading past end)
        // - Infinite loops (zero-length message)
        // - Crashes (casting garbage data)
        if msg_len < std::mem::size_of::<NlMsgHdr>() {
            return Err(MessageError::new(format!(
                "Invalid message length: {} (minimum is {})",
                msg_len,
                std::mem::size_of::<NlMsgHdr>()
            )));
        }

        if offset + msg_len > data.len() {
            return Err(MessageError::new(format!(
                "Message length {} exceeds buffer size (offset={}, buffer={})",
                msg_len,
                offset,
                data.len()
            )));
        }

        // === Handle different message types ===
        //
        // The nlmsg_type field tells us what kind of message this is.
        match nlh.nlmsg_type {
            NLMSG_DONE => {
                // End of multi-part message
                // No more data to parse, we're done!
                messages.push(ParsedMessage::Done);
                break;
            }

            NLMSG_ERROR => {
                // Error response from kernel
                //
                // This could be:
                // - Actual error (errno > 0): connection not found, permission denied, etc.
                // - ACK (errno == 0): successful acknowledgment
                let errno = parse_error_message(&data[offset..offset + msg_len])?;
                messages.push(ParsedMessage::Error(errno));

                if errno != 0 {
                    // Non-zero errno is actual error, stop parsing
                    break;
                }
                // errno == 0 is ACK, continue to next message
            }

            SOCK_DIAG_BY_FAMILY => {
                // Parse inet_diag_msg (connection information)
                //
                // Message structure:
                // [ NlMsgHdr ] [ InetDiagMsg ] [ Attributes... ]
                let msg_start = offset + std::mem::size_of::<NlMsgHdr>();

                // Verify buffer has space for InetDiagMsg
                if msg_start + std::mem::size_of::<InetDiagMsg>() > data.len() {
                    return Err(MessageError::new(
                        "Buffer too small for inet_diag_msg".to_string(),
                    ));
                }

                // SAFETY: Cast bytes to InetDiagMsg structure
                //
                // Why is this safe?
                // 1. We verified buffer size above
                // 2. Data is aligned (Netlink guarantees 4-byte alignment)
                // 3. InetDiagMsg is #[repr(C)] POD type
                // 4. We immediately copy the structure (not holding reference)
                let diag_msg = unsafe {
                    let ptr = data[msg_start..].as_ptr() as *const InetDiagMsg;
                    *ptr // Copy structure (not reference)
                };

                // === Parse attributes (TLV format) ===
                //
                // Attributes are optional key-value pairs following InetDiagMsg.
                // They contain things like:
                // - INET_DIAG_INFO: tcp_info structure (what we want!)
                // - INET_DIAG_CONG: congestion algorithm name
                // - INET_DIAG_MEMINFO: memory usage
                let attr_start = msg_start + std::mem::size_of::<InetDiagMsg>();
                let attr_end = offset + msg_len;

                let attributes = if attr_end > attr_start {
                    // We have attributes, parse them
                    parse_attributes(&data[attr_start..attr_end])?
                } else {
                    // No attributes, empty map
                    HashMap::new()
                };

                messages.push(ParsedMessage::InetDiag {
                    msg: diag_msg,
                    attributes,
                });
            }

            _ => {
                // Unknown message type
                //
                // This shouldn't happen, but we handle it gracefully.
                // Log a warning and skip this message.
                eprintln!("Unknown Netlink message type: {}", nlh.nlmsg_type);
            }
        }

        // === Move to next message ===
        //
        // Messages are aligned to 4-byte boundaries, so we use nlmsg_align()
        // Example: message of 73 bytes occupies 76 bytes (73 rounded up to multiple of 4)
        offset += nlmsg_align(msg_len);
    }

    Ok(messages)
}

/// Parse routing attributes from message tail
///
/// Attributes use TLV (Type-Length-Value) encoding, a common pattern in binary protocols.
/// Each attribute has a header (type + length) followed by payload data.
///
/// # Attribute Format
///
/// ```text
/// ┌────────────────┐
/// │ RtAttr header  │ ← 4 bytes (rta_len: u16, rta_type: u16)
/// ├────────────────┤
/// │ Payload        │ ← N bytes (actual data)
/// ├────────────────┤
/// │ Padding        │ ← 0-3 bytes (align to 4-byte boundary)
/// └────────────────┘
/// ```
///
/// # Parameters
///
/// * `data` - Attribute data bytes (everything after InetDiagMsg)
///
/// # Returns
///
/// HashMap mapping attribute type → payload bytes
///
/// Example:
/// - Key: INET_DIAG_INFO (2) → Value: tcp_info bytes
/// - Key: INET_DIAG_CONG (4) → Value: "cubic\0" bytes
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::message::parse_attributes;
/// # use cerberus::netlink::structures::INET_DIAG_INFO;
/// # let attr_data = vec![0u8; 200];
/// let attrs = parse_attributes(&attr_data)?;
///
/// if let Some(tcp_info_bytes) = attrs.get(&INET_DIAG_INFO) {
///     println!("Got tcp_info ({} bytes)", tcp_info_bytes.len());
///     // Now parse tcp_info structure from these bytes...
/// }
/// # Ok::<(), cerberus::netlink::message::MessageError>(())
/// ```
pub fn parse_attributes(data: &[u8]) -> Result<HashMap<u16, Vec<u8>>, MessageError> {
    let mut attrs = HashMap::new();
    let mut offset = 0;

    // === Iterate through TLV attributes ===
    //
    // Each attribute has:
    // - RtAttr header (4 bytes): length + type
    // - Payload (variable bytes)
    // - Padding to 4-byte boundary
    while offset + std::mem::size_of::<RtAttr>() <= data.len() {
        // === Parse attribute header ===
        //
        // SAFETY: Cast bytes to RtAttr structure
        //
        // Why is this safe?
        // 1. We verified buffer has at least size_of::<RtAttr>() bytes
        // 2. Data is aligned (Netlink ensures 4-byte alignment)
        // 3. RtAttr is #[repr(C)] POD type (rta_len: u16, rta_type: u16)
        // 4. We only read, never modify
        let rta = unsafe { &*(data[offset..].as_ptr() as *const RtAttr) };

        let attr_len = rta.rta_len as usize;

        // === Validate attribute length ===
        //
        // Check for end of attributes (length too small) or truncated data
        if attr_len < std::mem::size_of::<RtAttr>() {
            // This is normal - it means we've reached the end
            break;
        }

        if offset + attr_len > data.len() {
            return Err(MessageError::new(format!(
                "Attribute length {} exceeds buffer (offset={}, buffer={})",
                attr_len,
                offset,
                data.len()
            )));
        }

        // === Extract payload ===
        //
        // Payload starts after header and runs until end of attribute
        let payload_start = offset + std::mem::size_of::<RtAttr>();
        let payload_end = offset + attr_len;
        let payload = data[payload_start..payload_end].to_vec();

        // === Store attribute ===
        //
        // HashMap<u16, Vec<u8>> maps type number to payload bytes
        // Examples:
        // - INET_DIAG_INFO (2) → tcp_info bytes (192+ bytes)
        // - INET_DIAG_CONG (4) → "cubic\0" (6 bytes)
        attrs.insert(rta.rta_type, payload);

        // === Move to next attribute ===
        //
        // Attributes are aligned to 4-byte boundaries
        // Example: attribute of 7 bytes occupies 8 bytes (7 rounded up)
        offset += rta_align(attr_len);
    }

    Ok(attrs)
}

/// Parse error message payload
///
/// Error messages contain errno from kernel, indicating what went wrong.
///
/// # Error Message Format
///
/// ```text
/// ┌────────────────┐
/// │ NlMsgHdr       │ ← Netlink header (type = NLMSG_ERROR)
/// ├────────────────┤
/// │ errno (i32)    │ ← Negative error code (kernel convention)
/// ├────────────────┤
/// │ Original msg   │ ← The request that caused error
/// └────────────────┘
/// ```
///
/// # Parameters
///
/// * `data` - Error message bytes (entire message including header)
///
/// # Returns
///
/// Error code (errno) as positive number:
/// - 0 = ACK (success)
/// - 2 = ENOENT (not found)
/// - 13 = EACCES (permission denied)
/// - etc.
///
/// # Kernel Convention
///
/// Linux kernel sends errno as **negative** number (e.g., -2 for ENOENT).
/// We convert to positive for standard errno values.
///
/// # Example
///
/// ```no_run
/// # use cerberus::netlink::message::parse_error_message;
/// # let error_msg_bytes = vec![0u8; 32];
/// let errno = parse_error_message(&error_msg_bytes)?;
///
/// match errno {
///     0 => println!("ACK - success"),
///     2 => println!("Connection not found (ENOENT)"),
///     13 => println!("Permission denied (EACCES)"),
///     _ => println!("Other error: {}", errno),
/// }
/// # Ok::<(), cerberus::netlink::message::MessageError>(())
/// ```
pub fn parse_error_message(data: &[u8]) -> Result<i32, MessageError> {
    let header_size = std::mem::size_of::<NlMsgHdr>();

    // Verify buffer has space for header + errno
    if data.len() < header_size + 4 {
        return Err(MessageError::new("Error message too small".to_string()));
    }

    // === Read errno ===
    //
    // errno comes right after header (4 bytes, i32)
    let errno_bytes = &data[header_size..header_size + 4];

    // Convert 4 bytes to i32 using native endian
    // (host byte order, since Netlink uses native endian for headers)
    let errno = i32::from_ne_bytes([
        errno_bytes[0],
        errno_bytes[1],
        errno_bytes[2],
        errno_bytes[3],
    ]);

    // === Convert kernel errno to positive ===
    //
    // Kernel sends negative errno (e.g., -2 for ENOENT)
    // We convert to positive for standard errno values
    //
    // Why negative? Kernel convention to distinguish errno from valid return values.
    // In kernel, successful syscalls return >= 0, errors return negative errno.
    Ok(-errno)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_request() {
        // Build a simple request
        let sock_id = build_exact_socket_id(
            Ipv4Addr::new(192, 168, 1, 100),
            8080,
            Ipv4Addr::new(10, 0, 1, 5),
            5000,
        );

        let req = InetDiagReqV2 {
            sdiag_family: AF_INET,
            sdiag_protocol: IPPROTO_TCP,
            idiag_ext: 1 << (INET_DIAG_INFO - 1),
            pad: 0,
            idiag_states: 1 << TCP_ESTABLISHED,
            id: sock_id,
        };

        let message = build_inet_diag_request(&req, 12345);

        // Verify message structure
        assert!(
            message.len() >= 72,
            "Message should be at least 72 bytes (header + payload)"
        );
        assert_eq!(message.len() % 4, 0, "Message should be 4-byte aligned");

        // Verify header by casting back
        let nlh = unsafe { &*(message.as_ptr() as *const NlMsgHdr) };
        assert_eq!(nlh.nlmsg_type, SOCK_DIAG_BY_FAMILY);
        assert_eq!(nlh.nlmsg_seq, 12345);
        assert_eq!(nlh.nlmsg_flags, NLM_F_REQUEST | NLM_F_DUMP);
    }

    #[test]
    fn test_parse_done_message() {
        // Build a simple NLMSG_DONE message
        let mut data = Vec::new();

        let nlh = NlMsgHdr {
            nlmsg_len: std::mem::size_of::<NlMsgHdr>() as u32,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                std::mem::size_of::<NlMsgHdr>(),
            )
        };
        data.extend_from_slice(header_bytes);

        // Parse it
        let messages = parse_netlink_messages(&data).expect("Should parse successfully");

        assert_eq!(messages.len(), 1);
        match &messages[0] {
            ParsedMessage::Done => {}
            _ => panic!("Expected Done message"),
        }
    }

    #[test]
    fn test_parse_error_message_ack() {
        // Build ACK message (errno = 0)
        let mut data = Vec::new();

        let nlh = NlMsgHdr {
            nlmsg_len: (std::mem::size_of::<NlMsgHdr>() + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                std::mem::size_of::<NlMsgHdr>(),
            )
        };
        data.extend_from_slice(header_bytes);

        // errno = 0 (ACK)
        data.extend_from_slice(&0i32.to_ne_bytes());

        let errno = parse_error_message(&data).expect("Should parse successfully");
        assert_eq!(errno, 0, "ACK should have errno 0");
    }

    #[test]
    fn test_parse_error_message_enoent() {
        // Build error message (errno = ENOENT = -2)
        let mut data = Vec::new();

        let nlh = NlMsgHdr {
            nlmsg_len: (std::mem::size_of::<NlMsgHdr>() + 4) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                std::mem::size_of::<NlMsgHdr>(),
            )
        };
        data.extend_from_slice(header_bytes);

        // errno = -2 (kernel sends negative)
        data.extend_from_slice(&(-2i32).to_ne_bytes());

        let errno = parse_error_message(&data).expect("Should parse successfully");
        assert_eq!(errno, 2, "ENOENT should be errno 2");
    }

    #[test]
    fn test_parse_attributes_empty() {
        // Empty attribute data
        let data: Vec<u8> = Vec::new();
        let attrs = parse_attributes(&data).expect("Should handle empty data");
        assert_eq!(attrs.len(), 0);
    }

    #[test]
    fn test_parse_attributes_single() {
        // Build a single attribute manually
        let mut data = Vec::new();

        // RtAttr header: rta_len = 8, rta_type = 2 (INET_DIAG_INFO)
        let rta = RtAttr {
            rta_len: 8, // 4 bytes header + 4 bytes payload
            rta_type: INET_DIAG_INFO,
        };

        let rta_bytes = unsafe {
            std::slice::from_raw_parts(&rta as *const _ as *const u8, std::mem::size_of::<RtAttr>())
        };
        data.extend_from_slice(rta_bytes);

        // Payload: 4 bytes
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Parse
        let attrs = parse_attributes(&data).expect("Should parse successfully");

        assert_eq!(attrs.len(), 1);
        assert!(attrs.contains_key(&INET_DIAG_INFO));
        assert_eq!(attrs[&INET_DIAG_INFO], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_attributes_multiple() {
        // Build two attributes
        let mut data = Vec::new();

        // Attribute 1: type=2, payload=[0x11, 0x22]
        let rta1 = RtAttr {
            rta_len: 6, // 4 bytes header + 2 bytes payload
            rta_type: 2,
        };
        let rta1_bytes = unsafe {
            std::slice::from_raw_parts(
                &rta1 as *const _ as *const u8,
                std::mem::size_of::<RtAttr>(),
            )
        };
        data.extend_from_slice(rta1_bytes);
        data.extend_from_slice(&[0x11, 0x22]);

        // Padding to 4-byte boundary (6 bytes → 8 bytes)
        data.extend_from_slice(&[0x00, 0x00]);

        // Attribute 2: type=4, payload=[0x33, 0x44, 0x55, 0x66]
        let rta2 = RtAttr {
            rta_len: 8, // 4 bytes header + 4 bytes payload
            rta_type: 4,
        };
        let rta2_bytes = unsafe {
            std::slice::from_raw_parts(
                &rta2 as *const _ as *const u8,
                std::mem::size_of::<RtAttr>(),
            )
        };
        data.extend_from_slice(rta2_bytes);
        data.extend_from_slice(&[0x33, 0x44, 0x55, 0x66]);

        // Parse
        let attrs = parse_attributes(&data).expect("Should parse successfully");

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[&2], vec![0x11, 0x22]);
        assert_eq!(attrs[&4], vec![0x33, 0x44, 0x55, 0x66]);
    }
}
