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
#[derive(Debug)]
struct IpPacket {
    protocol: PacketType,
    destination: Ipv4Addr,
    source: Ipv4Addr,
    dest_port: u16,
    src_port: u16,
    length: usize,
}
#[derive(Debug)]
enum PacketType {
    Udp,
    Tcp(Vec<TcpFlag>),
    Dns(String),
    Other(String),
}
#[derive(Debug)]
enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
}

impl IpPacket {
    fn default() -> Self {
        Self {
            protocol: PacketType::Other(String::new()),
            destination: Ipv4Addr::new(0, 0, 0, 0),
            source: Ipv4Addr::new(0, 0, 0, 0),
            dest_port: 0,
            src_port: 0,
            length: 0,
        }
    }
    fn other(prot: String, dest: Ipv4Addr, src: Ipv4Addr) -> Self {
        Self {
            protocol: PacketType::Other(prot),
            destination: dest,
            source: src,
            dest_port: 0,
            src_port: 0,
            length: 0,
        }
    }
}

fn main() {
    let mut packets: Vec<IpPacket> = Vec::new();
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
                if let Some(eth) = EthernetPacket::new(raw)
                    && eth.get_ethertype() == EtherTypes::Ipv4
                    && let Some(packet) = handle_ipv4(eth.payload())
                {
                    packets.push(packet);
                }
            }
            Err(e) => eprintln!("read error: {e}"),
        }
        dbg!(&packets);
    }
}

fn handle_ipv4(payload: &[u8]) -> Option<IpPacket> {
    let pkt = Ipv4Packet::new(payload)?;

    let src = pkt.get_source();
    let dest = pkt.get_destination();

    match pkt.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some((srcport, dstport, flaglist, length)) = handle_tcp(pkt.payload()) {
                Some(IpPacket {
                    protocol: PacketType::Tcp(flaglist),
                    destination: dest,
                    source: src,
                    dest_port: dstport,
                    src_port: srcport,
                    length,
                })
            } else {
                None
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some((srcport, dstport, length, dnsquery)) = handle_udp(src, dest, pkt.payload())
            {
                match dnsquery {
                    Some(name) => Some(IpPacket {
                        protocol: PacketType::Dns(name),
                        destination: dest,
                        source: src,
                        dest_port: dstport,
                        src_port: srcport,
                        length,
                    }),
                    None => Some(IpPacket {
                        protocol: PacketType::Udp,
                        destination: dest,
                        source: src,
                        dest_port: dstport,
                        src_port: srcport,
                        length,
                    }),
                }
            } else {
                None
            }
        }
        other => Some(IpPacket::other(other.to_string(), dest, src)),
    }
}

fn handle_tcp(payload: &[u8]) -> Option<(u16, u16, Vec<TcpFlag>, usize)> {
    let tcp = TcpPacket::new(payload)?;

    let flags = tcp.get_flags();
    let mut flaglist = Vec::new();
    if flags & TcpFlags::SYN != 0 {
        flaglist.push(TcpFlag::Syn);
    }
    if flags & TcpFlags::ACK != 0 {
        flaglist.push(TcpFlag::Ack);
    }
    if flags & TcpFlags::FIN != 0 {
        flaglist.push(TcpFlag::Fin);
    }
    if flags & TcpFlags::RST != 0 {
        flaglist.push(TcpFlag::Rst);
    }
    if flags & TcpFlags::PSH != 0 {
        flaglist.push(TcpFlag::Psh);
    }
    // println!(
    //     "{src}:{} -> {dest}:{} [TCP {}] len={}",
    //     tcp.get_source(),
    //     tcp.get_destination(),
    //     flaglist.join(" "),
    //     tcp.payload().len(),
    // );
    Some((
        tcp.get_source(),
        tcp.get_destination(),
        flaglist,
        tcp.payload().len(),
    ))
}

fn handle_udp(
    src: Ipv4Addr,
    dest: Ipv4Addr,
    payload: &[u8],
) -> Option<(u16, u16, usize, Option<String>)> {
    let udp = UdpPacket::new(payload)?;

    if (udp.get_source() == 53 || udp.get_destination() == 53)
        && let Some(name) = parse_dns(udp.payload())
    {
        return Some((
            udp.get_source(),
            udp.get_destination(),
            udp.payload().len(),
            Some(name),
        ));
    }

    println!(
        "{src}:{} -> {dest}:{} [UDP] len={}",
        udp.get_source(),
        udp.get_destination(),
        udp.payload().len(),
    );
    Some((
        udp.get_source(),
        udp.get_destination(),
        udp.payload().len(),
        None,
    ))
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
