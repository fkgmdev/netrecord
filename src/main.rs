use std::net::Ipv4Addr;

use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::{
        Packet,
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::{TcpFlags, TcpPacket},
        udp::UdpPacket,
    },
};

fn main() {
    let iface = pick_interface();
    println!("listening on {}", iface.name);

    let (_tx, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unsupported channel type"),
        Err(e) => panic!("failed: {e} (check perms)"),
    };

    loop {
        match rx.next() {
            Ok(raw) => {
                if let Some(eth) = EthernetPacket::new(raw) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        handle_ipv4(eth.payload());
                    }
                }
            }
            Err(e) => eprintln!("read error: {e}"),
        }
    }
}

fn handle_ipv4(payload: &[u8]) {
    let Some(pkt) = Ipv4Packet::new(payload) else {
        return;
    };

    let src = pkt.get_source();
    let dest = pkt.get_destination();

    match pkt.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => handle_tcp(src, dest, pkt.payload()),
        IpNextHeaderProtocols::Udp => handle_udp(src, dest, pkt.payload()),
        other => println!("{src} -> {dest} other protocol: {other}"),
    }
}

fn handle_tcp(src: Ipv4Addr, dest: Ipv4Addr, payload: &[u8]) {
    let Some(tcp) = TcpPacket::new(payload) else {
        return;
    };

    let flags = tcp.get_flags();
    let mut flag_str = String::new();
    if flags & TcpFlags::SYN != 0 {
        flag_str.push_str("SYN ");
    }
    if flags & TcpFlags::ACK != 0 {
        flag_str.push_str("ACK ");
    }
    if flags & TcpFlags::FIN != 0 {
        flag_str.push_str("FIN ");
    }
    if flags & TcpFlags::RST != 0 {
        flag_str.push_str("RST ");
    }
    if flags & TcpFlags::PSH != 0 {
        flag_str.push_str("PSH ");
    }
    flag_str = flag_str.strip_suffix(" ").unwrap_or(&flag_str).to_string();
    println!(
        "{src}:{} -> {dest}:{} [TCP {}] len={}",
        tcp.get_source(),
        tcp.get_destination(),
        flag_str,
        tcp.payload().len(),
    )
}

fn handle_udp(src: Ipv4Addr, dest: Ipv4Addr, payload: &[u8]) {
    let Some(udp) = UdpPacket::new(payload) else {
        return;
    };

    if (udp.get_source() == 53 || udp.get_destination() == 53)
        && let Some(name) = parse_dns(udp.payload())
    {
        println!("{src} -> {dest} [DNS] query for {name}");
        return;
    }

    println!(
        "{src}:{} -> {dest}:{} [UDP] len={}",
        udp.get_source(),
        udp.get_destination(),
        udp.payload().len(),
    )
}

fn parse_dns(dns: &[u8]) -> Option<String> {
    if dns.len() < 12 {
        return None;
    }
    let mut name = String::new();
    let mut pos = 12;

    loop {
        let len = *dns.get(pos)? as usize;
        if len == 0 {
            break;
        }
        pos += 1;

        let label = dns.get(pos..pos + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        pos += len;
    }
    Some(name)
}

fn pick_interface() -> NetworkInterface {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .expect("no proper interfaces")
}
