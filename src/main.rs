use nente::{
    error::Error,
    netinfo::{
        self,
    },
    ethernet,
    ipv4,
    arp,
    icmp,
};
use std::{
    time,
    collections::HashMap,
    sync::{
        mpsc,
        Mutex,
    },
};

pub struct PendingQueries {
    arp: HashMap<ipv4::Addr, mpsc::Sender<ethernet::Addr>>
}

fn make_queries(
    iface: &dyn rawsock::traits::DynamicInterface,
    nic: &netinfo::NIC,
    pending: &Mutex<PendingQueries>,
) {
    let gateway_ip = nic.gateway;
    let (tx, rx) = mpsc::channel();
    {
        let mut pending = pending.lock().unwrap();
        pending.arp.insert(gateway_ip, tx);
    }
    
    let frame = ethernet::Frame {
        src: nic.phy_address,
        dst: ethernet::Addr::broadcast(),
        ether_type: Some(ethernet::EtherType::ARP),
        payload: ethernet::Payload::ARP(arp::Packet::request(nic)),
    };
    
    use cookie_factory as cf;
    let arp_serialized = cf::gen_simple(frame.serialize(), Vec::new()).unwrap();
    iface.send(&arp_serialized).unwrap();

    let gateway_phy_address = rx.recv().unwrap();
    println!("gateway physical address: {:?}", gateway_phy_address);

    let echo_frame = ethernet::Frame {
        src: nic.phy_address,
        dst: gateway_phy_address,
        ether_type: Some(ethernet::EtherType::IPv4),
        payload: ethernet::Payload::IPv4(ipv4::Packet::new(
            nic.address,
            ipv4::Addr([8, 8, 8, 8]),
            ipv4::Payload::ICMP(icmp::Packet::echo_request(
                icmp::Echo {
                    identifier: 0xBEEF,
                    sequence_number: 0xFACE,
                },
                "Lorem ipsum dolor sit amet".as_bytes(),
            )),
        )),
    };

    let serialized_echo = cf::gen_simple(echo_frame.serialize(), Vec::new()).unwrap();
    iface.send(&serialized_echo).unwrap();
}

fn process_packet(now: time::Duration, pending: &Mutex<PendingQueries>, packet: &rawsock::BorrowedPacket) {
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
            if let arp::Operation::Reply = arp_packet.operation {
                let mut pending = pending.lock().unwrap();
                if let Some(tx) = pending.arp.remove(&arp_packet.sender_ip_addr) {
                    tx.send(arp_packet.sender_hw_addr).unwrap();
                }
            }
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

    let pending = Mutex::new(PendingQueries {
        arp: HashMap::new(),
    });

    let start = time::Instant::now();
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| {
            make_queries(iface.as_ref(), &nic, &pending);
        });

        s.spawn(|_| {
            iface.loop_infinite_dyn(&mut |packet| {
                    process_packet(start.elapsed(), &pending, packet);
                 })
                 .unwrap();
        });
    })
    .unwrap();

    Ok(())
}