use nente::{
    error::Error,
    netinfo::{
        self,
    },
    ethernet,
    ipv4,
    arp,
};
use std::time;

fn process_packet(now: time::Duration, packet: &rawsock::BorrowedPacket) {
    let frame = match ethernet::Frame::parse(packet) {
        Ok((_remaining, frame)) => frame,
        Err(nom::Err::Error(e)) => {
            println!("{:?} | {:?}", now, e);
            return;
        }
        _ => unreachable!(),
    };

    match frame.payload {
        ethernet::Payload::IPv4(ref ip_packet) => match ip_packet.payload {
            ipv4::Payload::ICMP(ref icmp_packet) => println!(
                "{:?} | ({:?}) => ({:?}) | {:#?}",
                now, ip_packet.src, ip_packet.dst, icmp_packet
            ),
            _ => {}
        },
        ethernet::Payload::ARP(ref arp_packet) => {
            println!("{:?} | {:#?}", now, arp_packet);
        }
        _ => {}
    }
}

fn main() -> Result<(), Error> {
    let nic = netinfo::default_nic()?;
    println!("Using {:#?}", nic);

    let interface_name = format!(r#"\Device\NPF_{}"#, nic.guid);
    let lib = rawsock::open_best_library()?;
    let iface = lib.open_interface(&interface_name)?;

    let start = time::Instant::now();
    iface.loop_infinite_dyn(&mut |packet| {
        process_packet(start.elapsed(), packet);
    })?;

    Ok(())
}