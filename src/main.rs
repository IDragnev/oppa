use nente::{
    error::Error,
    netinfo::{
        self,
    },
    ethernet,
    ipv4,
};
use std::time;

fn process_packet(now: time::Duration, packet: &rawsock::BorrowedPacket) {
    match ethernet::Frame::parse(packet) {
        Ok((_remaining, frame)) => {
            if let ethernet::Payload::IPv4(ref packet) = frame.payload {
                if let Some(ipv4::Protocol::ICMP) = packet.protocol {
                    println!("{:?} | {:#?}", now, packet);
                }
            }
        },
        Err(nom::Err::Error(e)) => {
            println!("{:?} | {:?}", now, e);
        },
        _ => unreachable!(),
    }
}

fn main() -> Result<(), Error> {
    let nic_guid = netinfo::default_nic_guid()?;
    let interface_name = format!(r#"\Device\NPF_{}"#, nic_guid);
    let lib = rawsock::open_best_library()?;
    let iface = lib.open_interface(&interface_name)?;

    let start = time::Instant::now();
    iface.loop_infinite_dyn(&mut |packet| {
        process_packet(start.elapsed(), packet);
    })?;

    Ok(())
}