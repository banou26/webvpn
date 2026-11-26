use std::fmt;

/// Why bytes could not be read as the protocol lays them out. Each of these ends the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A body ends before its fields do.
    Truncated,
    /// A length is over the receiver's limit. Reported from the length alone, before the bytes it announces are
    /// buffered.
    TooLong,
    /// A field holds a value the protocol does not define.
    Invalid(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("a body ends before its fields do"),
            Self::TooLong => f.write_str("a length is over the limit"),
            Self::Invalid(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a request failed, as an `Error` reply carries it. A code this crate does not name is kept as it came, and a
/// receiver treats it as [`ErrorCode::OTHER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u16);

impl ErrorCode {
    /// The relay does not know the request or the option, or has the feature off.
    pub const UNSUPPORTED: Self = Self(1);
    /// The relay's policy refuses this target, port or option.
    pub const REFUSED: Self = Self(2);
    /// A limit is reached; the same request may pass later.
    pub const CAPACITY: Self = Self(3);
    /// The socket has too many requests waiting; nothing was applied.
    pub const BUSY: Self = Self(4);
    pub const AUTH_REQUIRED: Self = Self(5);
    /// The credential was not accepted; the session is as it was.
    pub const AUTH_FAILED: Self = Self(6);
    pub const UNKNOWN_SOCKET: Self = Self(7);
    pub const CONNECTION_REFUSED: Self = Self(16);
    pub const TIMED_OUT: Self = Self(17);
    pub const HOST_UNREACHABLE: Self = Self(18);
    pub const NETWORK_UNREACHABLE: Self = Self(19);
    pub const CONNECTION_RESET: Self = Self(20);
    pub const ADDRESS_IN_USE: Self = Self(21);
    pub const ADDRESS_NOT_AVAILABLE: Self = Self(22);
    /// The name has no address.
    pub const NAME_NOT_FOUND: Self = Self(23);
    /// The resolver did not answer.
    pub const LOOKUP_FAILED: Self = Self(24);
    /// The message says what happened.
    pub const OTHER: Self = Self(u16::MAX);
}

/// The code a session is closed with.
pub mod close {
    pub const NORMAL: u32 = 0;
    /// A frame could not be read, or setup did not finish in time.
    pub const PROTOCOL_ERROR: u32 = 1;
    pub const VERSION_MISMATCH: u32 = 2;
    pub const SESSION_LIMIT: u32 = 3;
    /// The relay is stopping; another session may be opened at once.
    pub const RESTARTING: u32 = 4;

    /// The WebSocket close code that carries a session close code.
    pub const fn websocket(code: u32) -> u16 {
        4000 + code as u16
    }
}

/// The code the relay resets its side of a socket's stream with.
pub mod reset {
    /// The client closed the socket.
    pub const CLOSED: u32 = 0;
    /// The peer reset the connection.
    pub const PEER_RESET: u32 = 1;
}
