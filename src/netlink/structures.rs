//! Binary structures for Netlink `INET_DIAG` protocol
//!
//! These structures use `#[repr(C)]` to match kernel layout exactly.
//! All multi-byte integers follow host byte order for Netlink headers,
//! and network byte order (big-endian) for IP addresses and ports.

use std::net::Ipv4Addr;

// NETLINK MESSAGE HEADER

/// Netlink message header (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

// SOCKET IDENTIFICATION

/// Socket identification structure (48 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InetDiagSockId {
    pub idiag_sport: u16,
    pub idiag_dport: u16,
    pub idiag_src: [u32; 4],
    pub idiag_dst: [u32; 4],
    pub idiag_if: u32,
    pub idiag_cookie: [u32; 2],
}

// INET_DIAG REQUEST

/// `INET_DIAG` request structure (56 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InetDiagReqV2 {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub idiag_ext: u8,
    pub pad: u8,
    pub idiag_states: u32,
    pub id: InetDiagSockId,
}

// INET_DIAG RESPONSE

/// `INET_DIAG` response message (72 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InetDiagMsg {
    pub idiag_family: u8,
    pub idiag_state: u8,
    pub idiag_timer: u8,
    pub idiag_retrans: u8,
    pub id: InetDiagSockId,
    pub idiag_expires: u32,
    pub idiag_rqueue: u32,
    pub idiag_wqueue: u32,
    pub idiag_uid: u32,
    pub idiag_inode: u32,
}

// ROUTING ATTRIBUTE HEADER

/// Routing attribute header (4 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

// CONSTANTS

// Netlink message types
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;

// Netlink flags
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_MULTI: u16 = 2;
pub const NLM_F_ACK: u16 = 4;
pub const NLM_F_ECHO: u16 = 8;
pub const NLM_F_DUMP_INTR: u16 = 16;
pub const NLM_F_DUMP_FILTERED: u16 = 32;

// Request flags
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Address families
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

// Protocol numbers
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// TCP states
pub const TCP_ESTABLISHED: u32 = 1;
pub const TCP_SYN_SENT: u32 = 2;
pub const TCP_SYN_RECV: u32 = 3;
pub const TCP_FIN_WAIT1: u32 = 4;
pub const TCP_FIN_WAIT2: u32 = 5;
pub const TCP_TIME_WAIT: u32 = 6;
pub const TCP_CLOSE: u32 = 7;
pub const TCP_CLOSE_WAIT: u32 = 8;
pub const TCP_LAST_ACK: u32 = 9;
pub const TCP_LISTEN: u32 = 10;
pub const TCP_CLOSING: u32 = 11;

// INET_DIAG attributes
pub const INET_DIAG_NONE: u16 = 0;
pub const INET_DIAG_MEMINFO: u16 = 1;
pub const INET_DIAG_INFO: u16 = 2;
pub const INET_DIAG_VEGASINFO: u16 = 3;
pub const INET_DIAG_CONG: u16 = 4;
pub const INET_DIAG_TOS: u16 = 5;
pub const INET_DIAG_TCLASS: u16 = 6;
pub const INET_DIAG_SKMEMINFO: u16 = 7;
pub const INET_DIAG_SHUTDOWN: u16 = 8;

// HELPER FUNCTIONS

/// Align length to 4-byte boundary
#[must_use]
pub const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Calculate Netlink message length
#[must_use]
pub const fn nlmsg_length(payload_len: usize) -> u32 {
    (std::mem::size_of::<NlMsgHdr>() + payload_len) as u32
}

/// Calculate space needed for Netlink message
#[must_use]
pub const fn nlmsg_space(payload_len: usize) -> usize {
    nlmsg_align(std::mem::size_of::<NlMsgHdr>() + payload_len)
}

/// Align attribute length to 4-byte boundary
#[must_use]
pub const fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Calculate attribute length
#[must_use]
pub const fn rta_length(payload_len: usize) -> u16 {
    (std::mem::size_of::<RtAttr>() + payload_len) as u16
}

/// Calculate space needed for attribute
#[must_use]
pub const fn rta_space(payload_len: usize) -> usize {
    rta_align(std::mem::size_of::<RtAttr>() + payload_len)
}

// BUILDER HELPERS

/// Build `InetDiagSockId` for exact 4-tuple match
#[must_use]
pub fn build_exact_socket_id(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> InetDiagSockId {
    InetDiagSockId {
        idiag_sport: local_port.to_be(),
        idiag_dport: remote_port.to_be(),
        idiag_src: [u32::from(local_ip).to_be(), 0, 0, 0],
        idiag_dst: [u32::from(remote_ip).to_be(), 0, 0, 0],
        idiag_if: 0,
        idiag_cookie: [0, 0],
    }
}

/// Build `InetDiagSockId` for local socket match
#[must_use]
pub fn build_local_socket_id(local_ip: Ipv4Addr, local_port: u16) -> InetDiagSockId {
    InetDiagSockId {
        idiag_sport: local_port.to_be(),
        idiag_dport: 0,
        idiag_src: [u32::from(local_ip).to_be(), 0, 0, 0],
        idiag_dst: [0, 0, 0, 0],
        idiag_if: 0,
        idiag_cookie: [0, 0],
    }
}

/// Build `InetDiagSockId` for dump all
#[must_use]
pub const fn build_dump_all_socket_id() -> InetDiagSockId {
    InetDiagSockId {
        idiag_sport: 0,
        idiag_dport: 0,
        idiag_src: [0, 0, 0, 0],
        idiag_dst: [0, 0, 0, 0],
        idiag_if: 0,
        idiag_cookie: [0, 0],
    }
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(std::mem::size_of::<NlMsgHdr>(), 16);
        assert_eq!(std::mem::size_of::<InetDiagSockId>(), 48);
        assert_eq!(std::mem::size_of::<InetDiagReqV2>(), 56);
        assert_eq!(std::mem::size_of::<InetDiagMsg>(), 72);
        assert_eq!(std::mem::size_of::<RtAttr>(), 4);
    }

    #[test]
    fn test_alignment() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(2), 4);
        assert_eq!(nlmsg_align(3), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(72), 72);
        assert_eq!(nlmsg_align(73), 76);
    }

    #[test]
    fn test_message_length() {
        let payload_size = std::mem::size_of::<InetDiagReqV2>();
        let msg_len = nlmsg_length(payload_size);
        assert_eq!(msg_len, 72);
    }

    #[test]
    fn test_socket_id_builder() {
        let local = Ipv4Addr::new(192, 168, 1, 100);
        let remote = Ipv4Addr::new(10, 0, 1, 5);

        let sock_id = build_exact_socket_id(local, 8080, remote, 5000);

        assert_eq!(sock_id.idiag_sport, 8080u16.to_be());
        assert_eq!(sock_id.idiag_dport, 5000u16.to_be());
        assert_eq!(sock_id.idiag_src[0], u32::from(local).to_be());
        assert_eq!(sock_id.idiag_dst[0], u32::from(remote).to_be());
    }
}
