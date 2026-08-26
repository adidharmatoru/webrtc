pub mod ffi;
pub use ffi::ifaces;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum NextHop {
    Broadcast(::std::net::SocketAddr),
    Destination(::std::net::SocketAddr),
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Kind {
    Packet,
    Link,
    Ipv4,
    Ipv6,
    Unknow(i32),
}

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub kind: Kind,
    pub addr: Option<::std::net::SocketAddr>,
    pub mask: Option<::std::net::SocketAddr>,
    pub hop: Option<NextHop>,
}

#[cfg(test)]
mod ipv6_byte_order_test {
    #[test]
    fn the_wire_form_is_bytes_not_host_order_words() {
        // fe80::1 on the wire.
        let wire: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let correct = std::net::Ipv6Addr::from(wire);
        assert_eq!(correct, "fe80::1".parse::<std::net::Ipv6Addr>().unwrap());

        // What reading the same memory as [u16; 8] and calling `.into()` produces on a
        // little-endian host: each group byte-swapped.
        let as_words: [u16; 8] = [0x80fe, 0, 0, 0, 0, 0, 0, 0x0100];
        let wrong = std::net::Ipv6Addr::from(as_words);

        assert_ne!(
            wrong, correct,
            "if these ever compare equal the test has stopped proving anything"
        );
        assert_eq!(wrong, "80fe::100".parse::<std::net::Ipv6Addr>().unwrap());
    }
}
