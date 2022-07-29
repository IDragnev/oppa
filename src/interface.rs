use crate::{
    netinfo,
    arp,
    ipv4,
    ethernet,
    error,
};
use std::{
    sync::{
        mpsc,
        Arc,
        Mutex,
    },
    time,
};
use once_cell::sync::Lazy;

static RAWSOCK_LIB: Lazy<Box<dyn rawsock::traits::Library>> =
    Lazy::new(|| rawsock::open_best_library().unwrap());

struct PendingQueries {
    ipv4: Vec<Box<dyn Fn(&ipv4::Packet) -> bool + Send>>,
}

impl PendingQueries {
    pub fn new() -> Self {
        Self {
            ipv4: Vec::new(),
        }
    }
}

pub struct Interface {
    nic: netinfo::NIC,
    gateway_mac: ethernet::Addr,
    iface: Arc<dyn rawsock::traits::DynamicInterface<'static>>,
    pending: Arc<Mutex<PendingQueries>>,
}

impl Interface {
    pub fn open_default() -> Result<Self, error::Error> {
        let nic = netinfo::default_nic()?;
        let iface_name = format!(r#"\Device\NPF_{}"#, nic.guid);
        let iface = RAWSOCK_LIB.open_interface_arc(&iface_name)?;

        let pending = Arc::new(Mutex::new(PendingQueries::new()));

        let gateway_mac = crossbeam_utils::thread::scope(|s| {
            let (tx, rx) = mpsc::channel();
            let gateway_ip = nic.gateway;

            let poll_iface = iface.clone();
            s.spawn(move |_| {
                poll_iface.loop_infinite_dyn(&mut |packet| {
                    let frame = match ethernet::Frame::parse(packet) {
                        Ok((_remaining, frame)) => frame,
                        _ => return,
                    };
                    let arp = match frame.payload {
                        ethernet::Payload::ARP(x) => x,
                        _ => return,
                    };
                    if let arp::Operation::Reply = arp.operation {
                        if arp.sender_ip_addr == gateway_ip {
                            tx.send(arp.sender_hw_addr).unwrap();
                        }
                    }
                })
                .unwrap();
            });

            let frame = ethernet::Frame {
                src: nic.phy_address,
                dst: ethernet::Addr::broadcast(),
                ether_type: Some(ethernet::EtherType::ARP),
                payload: ethernet::Payload::ARP(arp::Packet::request(&nic)),
            };
            send_ethernet(iface.as_ref(), frame).unwrap();

            let ret = rx.recv_timeout(time::Duration::from_secs(3))
                        .map_err(|_| "ARP timeout")
                        .unwrap();
            iface.break_loop();
            ret
        })
        .unwrap();

        let res = Self {
            nic,
            gateway_mac,
            iface: iface.clone(),
            pending: pending.clone(),
        };

        std::thread::spawn(move || {
            iface.loop_infinite_dyn(&mut |packet| {
                let frame = match ethernet::Frame::parse(packet) {
                    Ok((_, frame)) => frame,
                    _ => return,
                };

                if let ethernet::Payload::IPv4(ref packet) = frame.payload {
                    let mut guard = pending.lock().unwrap();
                    if let Some(idx) = guard.ipv4.iter().position(|f| f(packet)) {
                        let _rem = guard.ipv4.remove(idx);
                    }
                }
            })
            .unwrap();
        });

        Ok(res)
    }

    pub fn send_ipv4(
        &self,
        payload: ipv4::Payload,
        addr: &ipv4::Addr,
    ) -> Result<(), error::Error> {
        let frame = ethernet::Frame {
            src: self.nic.phy_address,
            dst: self.gateway_mac,
            ether_type: Some(ethernet::EtherType::IPv4),
            payload: ethernet::Payload::IPv4(
                ipv4::Packet::new(
                    self.nic.address,
                    addr.clone(),
                    payload,
            )),
        };

       send_ethernet(self.iface.as_ref(), frame)
    }

    pub fn expect_ipv4<F, T>(&mut self, f: F) -> mpsc::Receiver<T>
    where
        F: Fn(&ipv4::Packet) -> Option<T> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();

        let mut guard = self.pending.lock().unwrap();
        guard.ipv4.push(Box::new(move |packet| {
            match f(&packet) {
                Some(val) => {
                    tx.send(val).unwrap_or(()); // ignore send errors
                    true
                }
                None => false,
            }
        }));

        rx
    }
}

fn send_ethernet(
    iface: &dyn rawsock::traits::DynamicInterface,
    frame: ethernet::Frame,
) -> Result<(), error::Error> {
    let serialized = cookie_factory::gen_simple(frame.serialize(), Vec::new()).unwrap();
    iface.send(&serialized)?;
    iface.flush();

    Ok(())
}