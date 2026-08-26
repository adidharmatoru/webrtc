use super::*;

#[tokio::test]
async fn test_local_interfaces() -> Result<()> {
    let vnet = Arc::new(Net::new(None));
    let interfaces = vnet.get_interfaces().await;
    let ips = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        false,
    )
    .await;

    let ips_with_loopback = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        true,
    )
    .await;
    assert!(ips_with_loopback.is_superset(&ips));
    assert!(!ips.iter().any(|ip| ip.is_loopback()));
    assert!(ips_with_loopback.iter().any(|ip| ip.is_loopback()));
    log::info!(
        "interfaces: {interfaces:?}, ips: {ips:?}, ips_with_loopback: {ips_with_loopback:?}"
    );
    Ok(())
}

/// Regression: gathering an IPv6 link-local address produces a candidate nothing can send to.
#[test]
fn ipv6_link_local_is_not_gatherable() {
    use super::is_unusable_link_local_v6;
    use std::net::IpAddr;

    for ip in ["fe80::1", "fe80::5c8d:9fec:4d5b:8565", "febf::1"] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            is_unusable_link_local_v6(&ip),
            "{ip} carries no zone index once gathered and can never be reached"
        );
    }

    // Everything a real peer is actually reachable on must survive.
    for ip in [
        "2405:6580:b940:3600:d0ae:49c6:4a2d:2772", // global
        "fd7a:115c:a1e0::1",                       // unique-local (Tailscale, WireGuard)
        "::1",                                     // loopback, filtered separately
        "fec0::1",                                 // deprecated site-local, not link-local
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            !is_unusable_link_local_v6(&ip),
            "{ip} must still be gatherable"
        );
    }

    let v4: IpAddr = "169.254.1.1".parse().unwrap();
    assert!(
        !is_unusable_link_local_v6(&v4),
        "IPv4 link-local is a separate question and is not this rule's business"
    );
}
