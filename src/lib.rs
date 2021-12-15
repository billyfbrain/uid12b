use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use hex::FromHexError;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};

static OID_COUNTER: Lazy<AtomicUsize> =
    Lazy::new(|| AtomicUsize::new(thread_rng().gen_range(0..=MAX_U24)));

const TIMESTAMP_SIZE: usize = 4;
const PROCESS_ID_SIZE: usize = 5;
const COUNTER_SIZE: usize = 3;

const TIMESTAMP_OFFSET: usize = 0;
const PROCESS_ID_OFFSET: usize = TIMESTAMP_OFFSET + TIMESTAMP_SIZE;
const COUNTER_OFFSET: usize = PROCESS_ID_OFFSET + PROCESS_ID_SIZE;

const MAX_U24: usize = 0xFF_FFFF;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidHexStringCharacter { c: char, index: usize, hex: String },
    InvalidHexStringLength { length: usize, hex: String },
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidHexStringCharacter { c, index, hex } => {
                write!(
                    fmt,
                    "invalid character '{}' was found at index {} in the provided hex string: \
                     \"{}\"",
                    c, index, hex
                )
            }
            Error::InvalidHexStringLength { length, hex } => {
                write!(
                    fmt,
                    "provided hex string representation must be exactly 12 bytes, instead got: \
                     \"{}\", length {}",
                    hex, length
                )
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Id {
    id: [u8; 12],
}

impl TryFrom<String> for Id {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse_str(value)
    }
}

impl From<[u8; 12]> for Id {
    fn from(bytes: [u8; 12]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl Into<String> for &Id {
    fn into(self) -> String {
        self.to_hex()
    }
}

impl Into<[u8; 12]> for Id {
    fn into(self) -> [u8; 12] {
        self.id
    }
}

impl Into<[u8; 12]> for &Id {
    fn into(self) -> [u8; 12] {
        self.id
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl Id {
    pub fn new() -> Self {
        let timestamp = Self::gen_timestamp();
        let process_id = Self::gen_process_id();
        let counter = Id::gen_count();

        let mut id: [u8; 12] = [0; 12];
        id[TIMESTAMP_OFFSET..(TIMESTAMP_SIZE + TIMESTAMP_OFFSET)]
            .clone_from_slice(&timestamp[..TIMESTAMP_SIZE]);
        id[PROCESS_ID_OFFSET..(PROCESS_ID_SIZE + PROCESS_ID_OFFSET)]
            .clone_from_slice(&process_id[..PROCESS_ID_SIZE]);
        id[COUNTER_OFFSET..(COUNTER_SIZE + COUNTER_OFFSET)]
            .clone_from_slice(&counter[..COUNTER_SIZE]);
        Self { id }
    }

    /// Gets an incremental 3-byte count.
    /// Represented in Big Endian.
    fn gen_count() -> [u8; 3] {
        let u_counter = OID_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Mod result instead of OID_COUNTER to prevent threading issues.
        let u = u_counter % (MAX_U24 + 1);

        // Convert usize to writable u64, then extract the first three bytes.
        let u_int = u as u64;

        let buf = u_int.to_be_bytes();
        let buf_u24: [u8; 3] = [buf[5], buf[6], buf[7]];
        buf_u24
    }

    /// Generate a random 5-byte array.
    fn gen_process_id() -> [u8; 5] {
        let buf = Lazy::new(|| thread_rng().gen());
        *buf
    }

    /// Generates a new timestamp representing the current seconds since epoch.
    /// Represented in Big Endian.
    fn gen_timestamp() -> [u8; 4] {
        let timestamp: u32 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock is before 1970")
            .as_secs()
            .try_into()
            .unwrap(); // will succeed until 2106 since timestamp is unsigned
        timestamp.to_be_bytes()
    }

    /// Constructs a new Id wrapper around the raw byte representation.
    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        Self { id: bytes }
    }

    pub const fn to_bytes(&self) -> [u8; 12] {
        self.id
    }

    /// Convert this [`Id`] to its hex string representation.
    pub fn to_hex(self) -> String {
        hex::encode(self.id)
    }

    /// Creates an Id using a 12-byte (24-char) hexadecimal string.
    pub fn parse_str(s: impl AsRef<str>) -> Result<Id> {
        let s = s.as_ref();

        let bytes: Vec<u8> = hex::decode(s.as_bytes()).map_err(|e| match e {
            FromHexError::InvalidHexCharacter { c, index } => Error::InvalidHexStringCharacter {
                c,
                index,
                hex: s.to_string(),
            },
            FromHexError::InvalidStringLength | FromHexError::OddLength => {
                Error::InvalidHexStringLength {
                    length: s.len(),
                    hex: s.to_string(),
                }
            }
        })?;
        if bytes.len() != 12 {
            Err(Error::InvalidHexStringLength {
                length: s.len(),
                hex: s.to_string(),
            })
        } else {
            let mut byte_array: [u8; 12] = [0; 12];
            byte_array[..].copy_from_slice(&bytes[..]);
            Ok(Id::from_bytes(byte_array))
        }
    }

    /// Retrieves the timestamp from an [`Id`].
    pub fn timestamp(&self) -> i64 {
        let mut buf = [0; 4];
        buf.copy_from_slice(&self.id[0..4]);
        u32::from_be_bytes(buf) as i64
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Id").field(&self.to_hex()).finish()
    }
}

#[cfg(test)]
mod test {
    use chrono::{offset::TimeZone, Utc};
    use std::sync::Mutex;

    use super::*;

    static LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn count_generated_is_big_endian() {
        let _guard = LOCK.lock().unwrap();
        let start = 1_122_866;
        OID_COUNTER.store(start, Ordering::SeqCst);

        // Test count generates correct value 1122866
        let count_bytes = Id::gen_count();

        let mut buf: [u8; 4] = [0; 4];
        buf[1..=COUNTER_SIZE].clone_from_slice(&count_bytes[..COUNTER_SIZE]);

        let count = u32::from_be_bytes(buf);
        assert_eq!(start as u32, count);

        // Test OID formats count correctly as big endian
        let id = Id::new();

        assert_eq!(0x11u8, id.to_bytes()[COUNTER_OFFSET]);
        assert_eq!(0x22u8, id.to_bytes()[COUNTER_OFFSET + 1]);
        assert_eq!(0x33u8, id.to_bytes()[COUNTER_OFFSET + 2]);
    }

    #[test]
    fn test_counter_overflow_u24_max() {
        let _guard = LOCK.lock().unwrap();
        let start = MAX_U24;
        OID_COUNTER.store(start, Ordering::SeqCst);
        let id = Id::new();
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET]);
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET + 1]);
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET + 2]);
        // Test counter overflows to 0 when set to MAX_24 + 1
        let id_new = Id::new();
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET]);
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET + 1]);
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET + 2]);
    }

    #[test]
    fn test_counter_overflow_usize_max() {
        let _guard = LOCK.lock().unwrap();
        let start = usize::max_value();
        OID_COUNTER.store(start, Ordering::SeqCst);
        // Test counter overflows to u24_max when set to usize_max
        let id = Id::new();
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET]);
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET + 1]);
        assert_eq!(0xFFu8, id.to_bytes()[COUNTER_OFFSET + 2]);
        // Test counter overflows to 0 when set to usize_max + 1
        let id_new = Id::new();
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET]);
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET + 1]);
        assert_eq!(0x00u8, id_new.to_bytes()[COUNTER_OFFSET + 2]);
    }

    #[test]
    fn test_display() {
        let id = Id::parse_str("53e37d08776f724e42000000").unwrap();
        assert_eq!(format!("{}", id), "53e37d08776f724e42000000")
    }

    #[test]
    fn test_debug() {
        let id = Id::parse_str("53e37d08776f724e42000000").unwrap();

        assert_eq!(format!("{:?}", id), "Id(\"53e37d08776f724e42000000\")");
        assert_eq!(
            format!("{:#?}", id),
            "Id(\n    \"53e37d08776f724e42000000\",\n)"
        );
    }

    #[test]
    fn test_timestamp() {
        let id = Id::parse_str("000000000000000000000000").unwrap();
        // "Jan 1st, 1970 00:00:00 UTC"
        assert_eq!(
            Utc.ymd(1970, 1, 1).and_hms(0, 0, 0),
            Utc.timestamp(id.timestamp(), 0)
        );

        let id = Id::parse_str("7FFFFFFF0000000000000000").unwrap();
        // "Jan 19th, 2038 03:14:07 UTC"
        assert_eq!(
            Utc.ymd(2038, 1, 19).and_hms(3, 14, 7),
            Utc.timestamp(id.timestamp(), 0)
        );

        let id = Id::parse_str("800000000000000000000000").unwrap();
        // "Jan 19th, 2038 03:14:08 UTC"
        assert_eq!(
            Utc.ymd(2038, 1, 19).and_hms(3, 14, 8),
            Utc.timestamp(id.timestamp(), 0)
        );

        let id = Id::parse_str("FFFFFFFF0000000000000000").unwrap();
        // "Feb 7th, 2106 06:28:15 UTC"
        assert_eq!(
            Utc.ymd(2106, 2, 7).and_hms(6, 28, 15),
            Utc.timestamp(id.timestamp(), 0)
        );
    }
}
