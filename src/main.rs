use nente::{
    error::Error,
    netinfo::{
        self,
    },
    ethernet,
};
use std::time;

fn process_packet(now: time::Duration, packet: &rawsock::BorrowedPacket) {
    let frame = ethernet::Frame::parse(packet);
    println!("{:?} | {:?}", now, frame);
}

fn contains<H, N>(haystack: H, needle: N) -> bool
    where H: AsRef<[u8]>,
          N: AsRef<[u8]>,
{
    let (haystack, needle) = (haystack.as_ref(), needle.as_ref());
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn main() -> Result<(), Error> {
    let nic_guid = netinfo::default_nic_guid()?;
    let interface_name = format!(r#"\Device\NPF_{}"#, nic_guid);
    let lib = rawsock::open_best_library()?;
    let iface = lib.open_interface(&interface_name)?;

    let start = time::Instant::now();
    iface.loop_infinite_dyn(&mut |packet| {
        if contains(&packet[..], "abcdefghijkl") == false {
            println!("skipping a non-ICMP packet");
            return; // only process ICMP packets
        }

        process_packet(start.elapsed(), packet);
    })?;

    Ok(())
}