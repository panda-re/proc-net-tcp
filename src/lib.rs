//! Library for listing TCP sockets by parsing /proc/tcp/net

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::num::ParseIntError;

/// List of valid internal TCP states on Linux
///
/// From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp_states.h
#[repr(C)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Established = 1,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    MaxStates,
}

/// A socket entry as parsed from `/proc/net/tcp`
#[derive(Debug, Clone)]
pub struct RawSocketEntry {
    pub sl: i32,
    pub local_address: SocketAddrV4,
    pub remote_address: SocketAddrV4,
    pub state: TcpState,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub tr: u8,
    pub tm_when: u32,
    pub return_stmt: u32,
    pub uid: u32,
    pub timeout: u32,
    pub inode: u64,
}

#[derive(Debug)]
pub struct ParseFail;

fn parse_state(st: &str) -> Result<TcpState, ParseFail> {
    let st = i32::from_str_radix(st, 16).map_err(|_| ParseFail)?;

    use TcpState::*;

    Ok(match st {
        1 => Established,
        2 => SynSent,
        3 => SynRecv,
        4 => FinWait1,
        5 => FinWait2,
        6 => TimeWait,
        7 => Close,
        8 => CloseWait,
        9 => LastAck,
        0xa => Listen,
        0xb => Closing,
        0xc => NewSynRecv,
        _ => return Err(ParseFail),
    })
}

fn parse_address(addr: &str) -> Result<SocketAddrV4, ParseFail> {
    if addr.len() == 13 {
        let (addr, port) = addr.split_once(':').ok_or(ParseFail)?;

        let addr = u32::from_be(hex_u32(addr)?);
        let port = u16::from_str_radix(port, 16)?;

        Ok(SocketAddrV4::new(Ipv4Addr::from(addr), port))
    } else {
        Err(ParseFail)
    }
}

fn hex_u32(num: &str) -> Result<u32, ParseFail> {
    Ok(u32::from_str_radix(num, 16)?)
}

fn parse_tx_rx_queue(item: &str) -> Result<(u32, u32), ParseFail> {
    let (tx, rx) = item.split_once(':').ok_or(ParseFail)?;

    Ok((hex_u32(tx)?, hex_u32(rx)?))
}

fn parse_tr_tm_when(item: &str) -> Result<(u8, u32), ParseFail> {
    let (tr, tm_when) = item.split_once(':').ok_or(ParseFail)?;

    Ok((u8::from_str_radix(tr, 16)?, hex_u32(tm_when)?))
}

impl From<ParseIntError> for ParseFail {
    fn from(_: ParseIntError) -> Self {
        ParseFail
    }
}

fn parse_line(line: &str) -> Result<RawSocketEntry, ParseFail> {
    let mut items = line
        .split_ascii_whitespace()
        .filter(|item| !item.is_empty());

    let mut next = move || items.next().ok_or(ParseFail);

    let sl = next()?.trim_end_matches(':').parse()?;

    let local_address = parse_address(next()?)?;
    let remote_address = parse_address(next()?)?;

    let state = parse_state(next()?)?;

    let (tx_queue, rx_queue) = parse_tx_rx_queue(next()?)?;

    let (tr, tm_when) = parse_tr_tm_when(next()?)?;

    let return_stmt = hex_u32(next()?)?;

    let uid = next()?.parse()?;
    let timeout = next()?.parse()?;
    let inode = next()?.parse()?;

    Ok(RawSocketEntry {
        sl,
        local_address,
        remote_address,
        state,
        tx_queue,
        rx_queue,
        tr,
        tm_when,
        return_stmt,
        uid,
        timeout,
        inode,
    })
}

/// Lower level access to parser results
pub fn raw_socket_info(file_contents: &str) -> Vec<Result<RawSocketEntry, ParseFail>> {
    file_contents
        .split('\n')
        .filter(|line| !line.is_empty())
        .skip(1)
        .map(parse_line)
        .collect()
}

type Pid = u64;

/// Snapshot of information about a given TCP socket a specific point in time
/// to update this information, [`socket_info`] must be called again
#[derive(Debug, Clone)]
pub struct SocketEntry {
    /// Local address being bound to
    pub local_address: SocketAddrV4,

    /// Remote address being connected to
    pub remote_address: SocketAddrV4,

    /// Current internal state of this TCP socket
    pub state: TcpState,

    /// The timeout set on this socket
    pub timeout: u32,

    /// Process which owns the socket file descriptor. If this is `None` either the
    /// process has been killed or the current process doesn't have permission to access
    /// `/proc/{pid}`.
    pub owning_pid: Option<Pid>,

    /// File descriptor used within the owning process in order to access the socket.
    /// To access from another process use the symlink `/proc/{owning_pid}/fd/{fd}`
    ///
    /// If `None`, the owning process is either dead or the current process doesn't have
    /// permissions for `/proc/{owning_pid}`.
    pub fd: Option<RawFd>,

    inode: u64,
}

impl SocketEntry {
    /// Returns `true` if the state of the socket at time of the initial query is `Listen`
    pub fn is_listening(&self) -> bool {
        matches!(self.state, TcpState::Listen)
    }

    /// Returns the inode of the file the given socket is using for communication
    pub fn inode(&self) -> u64 {
        self.inode
    }
}

type InoMap = HashMap<u64, (Pid, RawFd)>;

fn from_raw_entry(
    entry: Result<RawSocketEntry, ParseFail>,
    ino_to_fd: &InoMap,
) -> Result<SocketEntry, ParseFail> {
    let RawSocketEntry {
        local_address,
        remote_address,
        state,
        timeout,
        inode,
        ..
    } = entry?;

    let (owning_pid, fd) = if let Some((pid, fd)) = ino_to_fd.get(&inode).cloned() {
        (Some(pid), Some(fd))
    } else {
        (None, None)
    };

    Ok(SocketEntry {
        local_address,
        remote_address,
        state,
        timeout,
        owning_pid,
        fd,
        inode,
    })
}

fn parse_os_u64(string: &OsStr) -> Option<u64> {
    string.to_str()?.parse().ok()
}

fn get_inode_fds(inodes: &HashSet<u64>) -> InoMap {
    let mut ino_to_fd = InoMap::new();

    for entry in fs::read_dir("/proc")
        .expect("Cannot read /proc")
        .filter_map(Result::ok)
    {
        // Only directories
        if entry.file_type().map_or(true, |x| !x.is_dir()) {
            continue;
        }

        // Only numeric dir names
        let pid = if let Some(pid) = parse_os_u64(&entry.file_name()) {
            pid
        } else {
            continue;
        };

        let fd_dir = if let Ok(dir) = fs::read_dir(entry.path().join("fd")) {
            dir.filter_map(Result::ok)
        } else {
            continue;
        };

        for fd_entry in fd_dir {
            if let Ok(metadata) = fs::metadata(fd_entry.path()) {
                let ino = metadata.ino();

                if inodes.contains(&ino) {
                    let fd = parse_os_u64(&fd_entry.file_name()).unwrap() as RawFd;
                    ino_to_fd.insert(ino, (pid, fd));
                }
            }
        }
    }

    ino_to_fd
}

/// Get a list of all bound TCP sockets as parsed from /proc/net/tcp
pub fn socket_info() -> Vec<Result<SocketEntry, ParseFail>> {
    let proc_tcp_net = fs::read_to_string("/proc/net/tcp").unwrap();

    let raw_sockets = raw_socket_info(&proc_tcp_net);

    let inodes: HashSet<_> = raw_sockets
        .iter()
        .filter_map(|socket| Some(socket.as_ref().ok()?.inode))
        .collect();

    let inode_to_fd = get_inode_fds(&inodes);

    let from_raw_entry = |entry| from_raw_entry(entry, &inode_to_fd);

    raw_sockets.into_iter().map(from_raw_entry).collect()
}
