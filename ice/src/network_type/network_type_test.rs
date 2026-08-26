use super::*;
use crate::error::Result;

#[test]
fn test_network_type_parsing_success() -> Result<()> {
    let ipv4: IpAddr = "192.168.0.1".parse().unwrap();
    let ipv6: IpAddr = "fe80::a3:6ff:fec4:5454".parse().unwrap();

    let tests = vec![
        ("lowercase UDP4", "udp", ipv4, NetworkType::Udp4),
        ("uppercase UDP4", "UDP", ipv4, NetworkType::Udp4),
        ("lowercase UDP6", "udp", ipv6, NetworkType::Udp6),
        ("uppercase UDP6", "UDP", ipv6, NetworkType::Udp6),
    ];

    for (name, in_network, in_ip, expected) in tests {
        let actual = determine_network_type(in_network, &in_ip)?;

        assert_eq!(
            actual, expected,
            "NetworkTypeParsing: '{name}' -- input:{in_network} expected:{expected} actual:{actual}"
        );
    }

    Ok(())
}

#[test]
fn test_network_type_parsing_failure() -> Result<()> {
    let ipv6: IpAddr = "fe80::a3:6ff:fec4:5454".parse().unwrap();

    let tests = vec![("invalid network", "junkNetwork", ipv6)];
    for (name, in_network, in_ip) in tests {
        let result = determine_network_type(in_network, &in_ip);
        assert!(
            result.is_err(),
            "NetworkTypeParsing should fail: '{name}' -- input:{in_network}",
        );
    }

    Ok(())
}

#[test]
fn test_network_type_is_udp() -> Result<()> {
    assert!(NetworkType::Udp4.is_udp());
    assert!(NetworkType::Udp6.is_udp());
    assert!(!NetworkType::Udp4.is_tcp());
    assert!(!NetworkType::Udp6.is_tcp());

    Ok(())
}

#[test]
fn test_network_type_is_tcp() -> Result<()> {
    assert!(NetworkType::Tcp4.is_tcp());
    assert!(NetworkType::Tcp6.is_tcp());
    assert!(!NetworkType::Tcp4.is_udp());
    assert!(!NetworkType::Tcp6.is_udp());

    Ok(())
}

#[test]
fn test_network_type_serialization() {
    let tests = vec![
        (NetworkType::Tcp4, "\"tcp4\""),
        (NetworkType::Tcp6, "\"tcp6\""),
        (NetworkType::Udp4, "\"udp4\""),
        (NetworkType::Udp6, "\"udp6\""),
        (NetworkType::Unspecified, "\"unspecified\""),
    ];

    for (network_type, expected_string) in tests {
        assert_eq!(
            expected_string.to_string(),
            serde_json::to_string(&network_type).unwrap()
        );
    }
}

#[test]
fn test_network_type_to_string() {
    let tests = vec![
        (NetworkType::Tcp4, "tcp4"),
        (NetworkType::Tcp6, "tcp6"),
        (NetworkType::Udp4, "udp4"),
        (NetworkType::Udp6, "udp6"),
        (NetworkType::Unspecified, "unspecified"),
    ];

    for (network_type, expected_string) in tests {
        assert_eq!(network_type.to_string(), expected_string);
    }
}

#[test]
fn test_remote_network_type_keys_on_the_remote_family() {
    use std::net::IpAddr;

    let v4: IpAddr = "192.168.1.5".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();

    // The transport half follows the local candidate; the family half follows the packet.
    assert_eq!(
        remote_network_type(NetworkType::Udp6, &v4),
        NetworkType::Udp4,
        "a v6 local candidate reading a v4 packet must look in the v4 bucket"
    );
    assert_eq!(
        remote_network_type(NetworkType::Udp4, &v6),
        NetworkType::Udp6
    );
    assert_eq!(
        remote_network_type(NetworkType::Tcp6, &v4),
        NetworkType::Tcp4,
        "transport must not be laundered into UDP"
    );
    assert_eq!(
        remote_network_type(NetworkType::Tcp4, &v6),
        NetworkType::Tcp6
    );
    assert_eq!(
        remote_network_type(NetworkType::Unspecified, &v4),
        NetworkType::Unspecified
    );

    // Same-family is unchanged.
    assert_eq!(
        remote_network_type(NetworkType::Udp4, &v4),
        NetworkType::Udp4
    );
    assert_eq!(
        remote_network_type(NetworkType::Udp6, &v6),
        NetworkType::Udp6
    );
}
