use oppa::{
    ipv4,
    icmp,
    Interface,
};
use std::{
    env,
    process,
    time,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = env::args().nth(1).unwrap_or_else(|| {
        println!("Usage: oppa DEST");
        process::exit(1);
    });

    let dest = arg.parse()?;

    let mut iface = Interface::open_default()?;

    let identifier = 0xBEEF;
    let data = "Lorem ipsum dolor sit amet";
    println!("Pinging {:?} with {} bytes of data:", dest, data.len());

    for sequence_number in 0..4 {
        let echo_pd = ipv4::Payload::ICMP(icmp::Packet::echo_request(
            icmp::Echo {
                identifier,
                sequence_number,
            },
            data.as_bytes(),
        ));

        let before = time::Instant::now();
        let rx = iface.expect_ipv4(move |packet| {
            if let ipv4::Payload::ICMP(ref icmp_packet) = packet.payload {
                if let icmp::Header::EchoReply(ref reply) = icmp_packet.header {
                    if reply.identifier == identifier && reply.sequence_number == sequence_number {
                        return Some((before.elapsed(), packet.clone()));
                    }
                }
            }

            None
        });

        iface.send_ipv4(echo_pd, &dest)?;

        match rx.recv_timeout(time::Duration::from_secs(3)) {
            Ok((elapsed, packet)) => {
                if let ipv4::Payload::ICMP(ref icmp_packet) = packet.payload {
                    if let icmp::Header::EchoReply(_) = icmp_packet.header {
                        println!(
                            "Reply from {:?}: bytes={} time={:?} TTL={}",
                            packet.src,
                            icmp_packet.payload.0.len(),
                            elapsed,
                            packet.ttl,
                        );
                    }
                }
            }
            Err(_) => {
                println!("Timed out!");
                process::exit(1);
            }
        }

        std::thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}