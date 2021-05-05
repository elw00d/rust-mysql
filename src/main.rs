use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::{io, thread, mem, fmt};
use std::time::Duration;
use std::str::FromStr;
use std::io::{Error, Read, Write};
use byteorder::{ByteOrder, LittleEndian, BigEndian, WriteBytesExt, LE};
use mem::size_of;
use bitflags::_core::cmp::max;
use sha1::{Sha1, Digest};
use std::collections::HashMap;
use linked_hash_map::LinkedHashMap;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

extern crate byteorder;
#[macro_use]
extern crate bitflags;
extern crate sha1;

bitflags! {
    struct CapabilityFlags: u32 {
        const CLIENT_LONG_PASSWORD = 0x00000001;
        const CLIENT_FOUND_ROWS = 0x00000002;
        const CLIENT_LONG_FLAG = 0x00000004;
        const CLIENT_CONNECT_WITH_DB = 0x00000008;
        const CLIENT_NO_SCHEMA = 0x00000010;
        const CLIENT_COMPRESS = 0x00000020;
        const CLIENT_ODBC = 0x00000040;
        const CLIENT_LOCAL_FILES = 0x00000080;
        const CLIENT_IGNORE_SPACE = 0x00000100;
        const CLIENT_PROTOCOL_41 = 0x00000200;
        const CLIENT_INTERACTIVE = 0x00000400;
        const CLIENT_SSL = 0x00000800;
        const CLIENT_IGNORE_SIGPIPE = 0x00001000;
        const CLIENT_TRANSACTIONS = 0x00002000;
        const CLIENT_RESERVED = 0x00004000;
        const CLIENT_SECURE_CONNECTION = 0x00008000;
        const CLIENT_MULTI_STATEMENTS = 0x00010000;
        const CLIENT_MULTI_RESULTS = 0x00020000;
        const CLIENT_PS_MULTI_RESULTS = 0x00040000;
        const CLIENT_PLUGIN_AUTH = 0x00080000;
        const CLIENT_CONNECT_ATTRS = 0x00100000;
        const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;
        const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000;
        const CLIENT_SESSION_TRACK = 0x00800000;
        const CLIENT_DEPRECATE_EOF = 0x01000000;
    }
}

bitflags! {
    struct BinlogDumpGtidFlags : u16 {
        const BINLOG_DUMP_NON_BLOCK = 0x0001;
        const BINLOG_THROUGH_POSITION = 0x0002;
        const BINLOG_THROUGH_GTID = 0x0004;
    }
}

/// https://dev.mysql.com/doc/refman/5.6/en/replication-gtids-concepts.html
struct GtidSet {
    map: LinkedHashMap<String, UuidSet>
}

struct UuidSet {
    server_uuid: String,
    intervals: Vec<Interval>,
}

struct Interval {
    start: u64,
    end: u64,
}

impl fmt::Display for CapabilityFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut enabled_flags = Vec::new();
        if self.intersects(CapabilityFlags::CLIENT_LONG_PASSWORD) {
            enabled_flags.push("CLIENT_LONG_PASSWORD")
        }
        if self.intersects(CapabilityFlags::CLIENT_FOUND_ROWS) {
            enabled_flags.push("CLIENT_FOUND_ROWS")
        }
        if self.intersects(CapabilityFlags::CLIENT_LONG_FLAG) {
            enabled_flags.push("CLIENT_LONG_FLAG")
        }
        if self.intersects(CapabilityFlags::CLIENT_CONNECT_WITH_DB) {
            enabled_flags.push("CLIENT_CONNECT_WITH_DB")
        }
        if self.intersects(CapabilityFlags::CLIENT_NO_SCHEMA) {
            enabled_flags.push("CLIENT_NO_SCHEMA")
        }
        if self.intersects(CapabilityFlags::CLIENT_COMPRESS) {
            enabled_flags.push("CLIENT_COMPRESS")
        }
        if self.intersects(CapabilityFlags::CLIENT_ODBC) {
            enabled_flags.push("CLIENT_ODBC")
        }
        if self.intersects(CapabilityFlags::CLIENT_LOCAL_FILES) {
            enabled_flags.push("CLIENT_LOCAL_FILES")
        }
        if self.intersects(CapabilityFlags::CLIENT_IGNORE_SPACE) {
            enabled_flags.push("CLIENT_IGNORE_SPACE")
        }
        if self.intersects(CapabilityFlags::CLIENT_PROTOCOL_41) {
            enabled_flags.push("CLIENT_PROTOCOL_41")
        }
        if self.intersects(CapabilityFlags::CLIENT_INTERACTIVE) {
            enabled_flags.push("CLIENT_INTERACTIVE")
        }
        if self.intersects(CapabilityFlags::CLIENT_SSL) {
            enabled_flags.push("CLIENT_SSL")
        }
        if self.intersects(CapabilityFlags::CLIENT_IGNORE_SIGPIPE) {
            enabled_flags.push("CLIENT_IGNORE_SIGPIPE")
        }
        if self.intersects(CapabilityFlags::CLIENT_TRANSACTIONS) {
            enabled_flags.push("CLIENT_TRANSACTIONS")
        }
        if self.intersects(CapabilityFlags::CLIENT_RESERVED) {
            enabled_flags.push("CLIENT_RESERVED")
        }
        if self.intersects(CapabilityFlags::CLIENT_SECURE_CONNECTION) {
            enabled_flags.push("CLIENT_SECURE_CONNECTION")
        }
        if self.intersects(CapabilityFlags::CLIENT_MULTI_STATEMENTS) {
            enabled_flags.push("CLIENT_MULTI_STATEMENTS")
        }
        if self.intersects(CapabilityFlags::CLIENT_MULTI_RESULTS) {
            enabled_flags.push("CLIENT_MULTI_RESULTS")
        }
        if self.intersects(CapabilityFlags::CLIENT_PS_MULTI_RESULTS) {
            enabled_flags.push("CLIENT_PS_MULTI_RESULTS")
        }
        if self.intersects(CapabilityFlags::CLIENT_PLUGIN_AUTH) {
            enabled_flags.push("CLIENT_PLUGIN_AUTH")
        }
        if self.intersects(CapabilityFlags::CLIENT_CONNECT_ATTRS) {
            enabled_flags.push("CLIENT_CONNECT_ATTRS")
        }
        if self.intersects(CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
            enabled_flags.push("CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA")
        }
        if self.intersects(CapabilityFlags::CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS) {
            enabled_flags.push("CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS")
        }
        if self.intersects(CapabilityFlags::CLIENT_SESSION_TRACK) {
            enabled_flags.push("CLIENT_SESSION_TRACK")
        }
        if self.intersects(CapabilityFlags::CLIENT_DEPRECATE_EOF) {
            enabled_flags.push("CLIENT_DEPRECATE_EOF")
        }
        write!(f, "{}", enabled_flags.join("|"))
    }
}

struct PacketHeader<'a> {
    payload_len: u32,
    seq_id: u8,
    payload: &'a [u8],
}

struct Handshake {
    protocol_version: u8,
    server_version: String,
    connection_id: u32,
    // concatenated auth_plugin_data_1 and auth_plugin_data_2
    auth_plugin_data: Vec<u8>,
    character_set: u8,
    status_flags: u16,
    auth_plugin_name: String,
    capability_flags: CapabilityFlags,
}

/// https://dev.mysql.com/doc/internals/en/binlog-event-header.html
struct BinlogEventHeader {
    /// seconds since unix epoch
    timestamp: u32,
    /// https://dev.mysql.com/doc/internals/en/binlog-event-type.html
    event_type: BinlogEventType,
    /// server-id of the originating mysql-server
    server_id: u32,
    /// size of the event (header, post-header, body)
    event_size: u32,
    /// position of the next event
    log_pos: u32,
    /// https://dev.mysql.com/doc/internals/en/binlog-event-flag.html
    flags: BinlogEventFlags,
}

/// https://dev.mysql.com/doc/internals/en/binlog-event-type.html
#[allow(non_camel_case_types)]
#[derive(FromPrimitive)]
enum BinlogEventType {
    UNKNOWN_EVENT = 0x00,
    START_EVENT_V3 = 0x01,
    QUERY_EVENT = 0x02,
    STOP_EVENT = 0x03,
    ROTATE_EVENT = 0x04,
    INTVAR_EVENT = 0x05,
    LOAD_EVENT = 0x06,
    SLAVE_EVENT = 0x07,
    CREATE_FILE_EVENT = 0x08,
    APPEND_BLOCK_EVENT = 0x09,
    EXEC_LOAD_EVENT = 0x0a,
    DELETE_FILE_EVENT = 0x0b,
    NEW_LOAD_EVENT = 0x0c,
    RAND_EVENT = 0x0d,
    USER_VAR_EVENT = 0x0e,
    FORMAT_DESCRIPTION_EVENT = 0x0f,
    XID_EVENT = 0x10,
    BEGIN_LOAD_QUERY_EVENT = 0x11,
    EXECUTE_LOAD_QUERY_EVENT = 0x12,
    TABLE_MAP_EVENT = 0x13,
    WRITE_ROWS_EVENTv0 = 0x14,
    UPDATE_ROWS_EVENTv0 = 0x15,
    DELETE_ROWS_EVENTv0 = 0x16,
    WRITE_ROWS_EVENTv1 = 0x17,
    UPDATE_ROWS_EVENTv1 = 0x18,
    DELETE_ROWS_EVENTv1 = 0x19,
    INCIDENT_EVENT = 0x1a,
    HEARTBEAT_EVENT = 0x1b,
    IGNORABLE_EVENT = 0x1c,
    ROWS_QUERY_EVENT = 0x1d,
    WRITE_ROWS_EVENTv2 = 0x1e,
    UPDATE_ROWS_EVENTv2 = 0x1f,
    DELETE_ROWS_EVENTv2 = 0x20,
    GTID_EVENT = 0x21,
    ANONYMOUS_GTID_EVENT = 0x22,
    PREVIOUS_GTIDS_EVENT = 0x23,
}

bitflags! {
    /// https://dev.mysql.com/doc/internals/en/binlog-event-flag.html
    struct BinlogEventFlags : u16 {
        const LOG_EVENT_BINLOG_IN_USE_F = 0x0001;
        const LOG_EVENT_FORCED_ROTATE_F = 0x0002;
        const LOG_EVENT_THREAD_SPECIFIC_F = 0x0004;
        const LOG_EVENT_SUPPRESS_USE_F = 0x0008;
        const LOG_EVENT_UPDATE_TABLE_MAP_VERSION_F = 0x0010;
        const LOG_EVENT_ARTIFICIAL_F = 0x0020;
        const LOG_EVENT_RELAY_LOG_F = 0x0040;
        const LOG_EVENT_IGNORABLE_F = 0x0080;
        const LOG_EVENT_NO_FILTER_F = 0x0100;
        const LOG_EVENT_MTS_ISOLATE_F = 0x0200;
    }
}

fn parse_null_terminated_str(buf: &[u8]) -> String {
    let mut vec = Vec::new();
    let mut i = 0;
    while i < buf.len() && buf[i] != 0_u8 {
        vec.push(buf[i]);
        i += 1;
    }
    return String::from_utf8(vec).unwrap();
}

fn parse_handshake(buf: &[u8]) -> Handshake {
    let mut offset = 0;
    let protocol_version = buf[offset];
    assert_eq!(protocol_version, 10, "unsupported protocol");
    offset += 1;
    let server_version = parse_null_terminated_str(&buf[offset..]);
    offset += server_version.len() + 1;
    let connection_id = LittleEndian::read_u32(&buf[offset..]);
    offset += mem::size_of::<u32>();

    let mut auth_plugin_data = Vec::new();
    auth_plugin_data.extend_from_slice(&buf[offset..offset + 8]);

    offset += 8;
    offset += 1;  // skip "filler" field
    let capability_flag_1 = LittleEndian::read_u16(&buf[offset..]);
    offset += mem::size_of::<u16>();

    // if more data in the packet
    assert!(buf.len() > offset);

    let character_set = buf[offset];
    offset += 1;
    let status_flags = LittleEndian::read_u16(&buf[offset..]);
    offset += mem::size_of::<u16>();
    let capability_flags_2 = LittleEndian::read_u16(&buf[offset..]);
    offset += mem::size_of::<u16>();

    let capability_flags = CapabilityFlags::from_bits_truncate(
        ((capability_flags_2 as u32) << 16) | (capability_flag_1 as u32)
    );

    assert!(capability_flags.intersects(CapabilityFlags::CLIENT_PLUGIN_AUTH));
    let auth_plugin_data_len = buf[offset] as usize;
    offset += 1;
    offset += 10;  // reserved
    assert!(capability_flags.intersects(CapabilityFlags::CLIENT_SECURE_CONNECTION));
    let auth_plugin_data_part2_len = max(13, auth_plugin_data_len - 8);
    auth_plugin_data.extend_from_slice(&buf[offset..offset + auth_plugin_data_part2_len]);
    offset += auth_plugin_data_part2_len;

    let auth_plugin_name = parse_null_terminated_str(&buf[offset..]);

    return Handshake {
        protocol_version,
        server_version,
        connection_id,
        auth_plugin_data,
        character_set,
        status_flags,
        auth_plugin_name,
        capability_flags,
    };
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> usize {
    buf.write_all(bytes);
    return bytes.len();
}

fn write_str(buf: &mut Vec<u8>, str: &str) -> usize {
    return write_bytes(buf, str.as_bytes());
}

fn write_null_terminated_str(buf: &mut Vec<u8>, str: &str) -> usize {
    let written = write_str(buf, str);
    buf.write_u8(0);
    return written + 1;
}

fn build_com_register_slave_cmd(server_id: u32) -> Vec<u8> {
    let mut buf = vec![0_u8; 4];  // 4 bytes reserved for packet header

    buf.write_u8(0x15);  // COM_REGISTER_SLAVE command
    buf.write_u32::<LittleEndian>(server_id);
    buf.write_u8(0);  // slaves hostname length
    buf.write_u8(0);  // slaves user len
    buf.write_u8(0);  // slaves password len
    buf.write_u16::<LittleEndian>(0);  // slaves mysql-port
    buf.write_u32::<LittleEndian>(0);  // replication rank
    buf.write_u32::<LittleEndian>(0);  // master-id

    // fill packet header
    let packet_len = (buf.len() - 4) as u32;
    LittleEndian::write_u24(&mut buf, packet_len);
    buf[3] = 0x00;  // seq_id

    return buf;
}

/// https://dev.mysql.com/doc/internals/en/com-binlog-dump-gtid.html
fn build_com_binlog_dump_gtid_cmd(server_id: u32, gtid_set: &GtidSet) -> Vec<u8> {
    let mut buf = vec![0_u8; 4];  // 4 bytes reserved for packet header

    buf.write_u8(0x1e);  // COM_BINLOG_DUMP_GTID command
    buf.write_u16::<LittleEndian>(BinlogDumpGtidFlags::BINLOG_THROUGH_GTID.bits);
    buf.write_u32::<LittleEndian>(server_id);
    buf.write_u32::<LittleEndian>(0);  // binlog-filename-len = 0
    buf.write_u64::<LittleEndian>(4);  // binlog-pos is always 4 (points to first byte after binlog file header)

    let mut data_buf = vec![];
    // mysql documentation notes that n_sids has 4 bytes length, but it is 8 bytes actually
    data_buf.write_u64::<LittleEndian>(gtid_set.map.len() as u64);
    for (uuid, uuid_set) in gtid_set.map.iter() {
        write_bytes(&mut data_buf, &hex::decode(uuid.replace("-", "")).unwrap());
        data_buf.write_u64::<LittleEndian>(uuid_set.intervals.len() as u64);
        for interval in uuid_set.intervals.iter() {
            data_buf.write_u64::<LittleEndian>(interval.start);
            data_buf.write_u64::<LittleEndian>(interval.end + 1);  // start reading next transaction
        }
    }
    buf.write_u32::<LittleEndian>(data_buf.len() as u32);
    write_bytes(&mut buf, &data_buf);

    // fill packet header TODO : extract fn
    let packet_len = (buf.len() - 4) as u32;
    LittleEndian::write_u24(&mut buf, packet_len);
    buf[3] = 0x00;  // seq_id

    return buf;
}

fn build_com_quit_cmd() -> Vec<u8> {
    let mut buf = vec![0_u8; 4];  // 4 bytes reserved for packet header

    buf.write_u8(0x01);  // COM_QUIT command

    // fill packet header
    let packet_len = (buf.len() - 4) as u32;
    LittleEndian::write_u24(&mut buf, packet_len);
    buf[3] = 0x00;  // seq_id

    return buf;
}

fn build_handshake_response(handshake: &Handshake, username: &str, password: &str) -> Vec<u8> {
    let mut buf = vec![0_u8; 4];  // 4 bytes reserved for packet header

    let capability_flags = CapabilityFlags::CLIENT_LONG_PASSWORD
        | CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_SECURE_CONNECTION
        | CapabilityFlags::CLIENT_DEPRECATE_EOF;
    buf.write_u32::<LittleEndian>(capability_flags.bits);
    buf.write_u32::<LittleEndian>(65535_u32);  // max_packet_size
    buf.write_u8(8);  // latin1 character set
    buf.write(&vec![0_u8; 23]);  // reserved
    write_null_terminated_str(&mut buf, username);

    let password = password;
    let scrambled_password = scramble_password(password, &handshake.auth_plugin_data[0..20].to_vec());

    buf.write_u8(scrambled_password.len() as u8);
    write_bytes(&mut buf, &scrambled_password);

    // fill packet header
    let packet_len = (buf.len() - 4) as u32;
    LittleEndian::write_u24(&mut buf, packet_len);
    buf[3] = 0x01;  // seq_id

    return buf;
}

/// Computes salted password
/// for Authentication::Native41 method (with CLIENT_SECURE_CONNECTION flag)
/// SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
fn scramble_password(password: &str, salt: &Vec<u8>) -> Vec<u8> {
    let password_sha = sha1(&password.as_bytes().to_vec());
    let double_sha1 = sha1(&password_sha);
    let mut salt_plus_double_sha1 = salt.clone();
    salt_plus_double_sha1.extend(double_sha1);
    let right_xor_arg = sha1(&salt_plus_double_sha1);

    let mut scrambled_password = Vec::new();
    let mut i = 0;
    while i < password_sha.len() {
        scrambled_password.write_u8(password_sha[i] ^ right_xor_arg[i]);
        i += 1;
    }

    return scrambled_password;
}

fn sha1(bytes: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

// 3 bytes for payload len, 1 byte for seq_id, 2^24 for payload
const MAX_MYSQL_PACKET_LEN: usize = 4 + (2 << 24);

fn parse_header(buf: &Vec<u8>) -> PacketHeader {
    let payload_len = LittleEndian::read_u24(&buf);
    let seq_id = buf[3];
    let payload = &buf[size_of::<u32>()..size_of::<u32>() + payload_len as usize];
    return PacketHeader {
        payload_len,
        seq_id,
        payload,
    };
}

/// Returns integer value and length of parsed data in bytes
/// Option::None is NULL value in ProtocolText::ResultsetRow context
fn parse_length_encoded_int(buf: &[u8]) -> (Option<u64>, usize) {
    match buf[0] {
        0xfb => (Option::None, 1),
        0xfc => (Option::Some(LittleEndian::read_u16(&buf[1..]) as u64), 3),
        0xfd => (Option::Some(LittleEndian::read_u24(&buf[1..]) as u64), 4),
        0xfe => (Option::Some(LittleEndian::read_u64(&buf[1..])), 9),
        0xff => panic!("unexpected 0xff prefix"),
        _ => (Option::Some(buf[0] as u64), 1)
    }
}

fn parse_binlog_event_header(packet: &PacketHeader) -> Result<BinlogEventHeader, GenericResponsePacket> {
    let payload = packet.payload;
    match payload[0] {
        0x00 => {
            let mut offset = 1_usize;

            let timestamp = LittleEndian::read_u32(&payload[offset..]);
            offset += 4;
            let event_type = BinlogEventType::from_u8(payload[offset]).unwrap();
            offset += 1;
            let server_id = LittleEndian::read_u32(&payload[offset..]);
            offset += 4;
            let event_size = LittleEndian::read_u32(&payload[offset..]);
            offset += 4;
            let log_pos = LittleEndian::read_u32(&payload[offset..]);
            offset += 4;
            let flags = BinlogEventFlags::from_bits(LE::read_u16(&payload[offset..])).unwrap();

            Result::Ok(BinlogEventHeader {
                timestamp,
                event_type,
                server_id,
                event_size,
                log_pos,
                flags,
            })
        }
        0xff => Err(parse_err_packet(payload)),
        0xfe => Err(GenericResponsePacket::Eof),
        _ => panic!("incorrect binlog event header")
    }
}

fn parse_generic_response(packet: &PacketHeader) -> GenericResponsePacket {
    let payload = packet.payload;
    return match payload[0] {
        0x00 => {
            let mut offset = 1_usize;

            let (affected_rows_opt, len) = parse_length_encoded_int(&payload[offset..]);
            offset += len;
            let affected_rows = affected_rows_opt.unwrap();

            let (last_insert_id_opt, len) = parse_length_encoded_int(&payload[offset..]);
            offset += len;
            let last_insert_id = last_insert_id_opt.unwrap();

            let status_flags = LittleEndian::read_u16(&payload[offset..]);
            offset += 2;
            let warnings = LittleEndian::read_u16(&payload[offset..]);
            offset += 2;

            let info = String::from_utf8_lossy(&payload[offset..]).to_string();

            GenericResponsePacket::Ok {
                affected_rows,
                last_insert_id,
                status_flags,
                warnings,
                info
            }
        }
        0xff => parse_err_packet(payload),
        0xfe => GenericResponsePacket::Eof,
        _ => panic!("unknown packet first byte")
    }
}

fn parse_err_packet(payload: &[u8]) -> GenericResponsePacket {
    assert_eq!(payload[0], 0xff);
    //
    let mut offset = 1_usize;
    let error_code = LittleEndian::read_u16(&payload[offset..]);
    offset += 2;
    let sql_state_marker = String::from_utf8_lossy(&payload[offset..offset + 1]).to_string();
    offset += 1;
    let sql_state = String::from_utf8_lossy(&payload[offset..offset + 5]).to_string();
    offset += 5;
    let error_message = String::from_utf8_lossy(&payload[offset..]).to_string();
    //
    GenericResponsePacket::Err {
        error_code,
        sql_state_marker,
        sql_state,
        error_message,
    }
}

enum GenericResponsePacket {
    Ok {
        affected_rows: u64,
        last_insert_id: u64,
        status_flags: u16,
        warnings: u16,
        /// human readable status information
        info: String,
    },
    Err {
        error_code: u16,
        sql_state_marker: String,
        sql_state: String,
        error_message: String,
    },
    Eof
}

fn real_main() -> i32 {
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name("settings")).unwrap();

    let settings_map = settings.try_into::<HashMap<String, String>>().unwrap();
    println!("{:?}", settings_map);

    let result = settings_map["address"].to_socket_addrs();
    let server: Vec<SocketAddr> = result.expect("Unable to resolve").collect();
    let result: io::Result<TcpStream> = TcpStream::connect_timeout(
        server.get(0).expect(""),
        Duration::from_secs(5));
    match result {
        Ok(mut stream) => {
            let mut buf = vec![0_u8; MAX_MYSQL_PACKET_LEN];

            stream.read(&mut buf);
            let payload_len = LittleEndian::read_u24(&buf);
            let seq_id = buf[3];
            let payload = &buf[size_of::<u32>()..size_of::<u32>() + payload_len as usize];
            let handshake = parse_handshake(payload);
            println!("{}", handshake.capability_flags);

            if !handshake.capability_flags.intersects(CapabilityFlags::CLIENT_PROTOCOL_41) {
                panic!("CLIENT_PROTOCOL_41 is not supported")
            }
            if handshake.auth_plugin_name != "mysql_native_password" {
                panic!("Unsupported auth method")
            }

            let handshake_response = build_handshake_response(
                &handshake,
                &settings_map["username"],
                &settings_map["password"],
            );

            stream.write(&handshake_response);

            stream.read(&mut buf);

            let header = parse_header(&buf);

            let packet = parse_generic_response(&header);

            match packet {
                GenericResponsePacket::Err { error_code, sql_state_marker, sql_state, error_message } => {
                    println!("{}", error_message);
                    return 1;
                }
                GenericResponsePacket::Eof => panic!("unexpected eof"),
                _ => {}
            }

            println!("f");

            let mut map = LinkedHashMap::new();
            map.insert(String::from("3785dbf8-f2f3-11ea-8114-da0aa51b98ab"), UuidSet {
                server_uuid: String::from("3785dbf8-f2f3-11ea-8114-da0aa51b98ab"),
                intervals: vec![Interval { start: 1, end: 29554687 }],
            });
            map.insert(String::from("5aeb83cb-f2f3-11ea-8737-a9bebf814aec"), UuidSet {
                server_uuid: String::from("5aeb83cb-f2f3-11ea-8737-a9bebf814aec"),
                intervals: vec![Interval { start: 1, end: 19328298 }],
            });
            let binlog_dump_gtid_cmd = build_com_binlog_dump_gtid_cmd(2345335, &GtidSet { map });
            stream.write(&binlog_dump_gtid_cmd);

            buf = vec![0_u8; MAX_MYSQL_PACKET_LEN];
            let f = stream.read(&mut buf).unwrap();

            // no need to register slave
            // let register_slave_cmd = build_com_register_slave_cmd(2345335);
            // stream.write(&register_slave_cmd);
            // stream.read(&mut buf);

            let header = parse_header(&buf);

            //let packet = parse_generic_response(&header);
            let event_header_result = parse_binlog_event_header(&header);
            match &event_header_result {
                Ok(event_heaeder) => {
                    println!("ok binlog event");
                }
                Err(error_packet) => {
                    println!("error");
                }
            }

            stream.write(&build_com_quit_cmd());
            stream.read(&mut buf);

            let header = parse_header(&buf);

            let packet = parse_generic_response(&header);

            println!("fff");
        }
        Err(e) => {
            println!("Failed to connect: {}", e)
        }
    }
    println!("Hello, world!");
    0
}

fn main() {
    let exit_code = real_main();
    std::process::exit(exit_code);
}
