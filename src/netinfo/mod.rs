#![allow(non_snake_case)]

mod vls;

use crate::{
    error,
    ipv4,
    ethernet,
};
use vls::VLS;
use std::{
    slice,
    fmt,
};
use custom_debug_derive::*;

crate::bind! {
    library "IPHLPAPI.dll";

    fn GetIpForwardTable(table: *mut IpForwardTable, size: *mut u32, order: bool) -> u32;
    fn GetInterfaceInfo(info: *mut IpInterfaceInfo, size: *mut u32) -> u32;
    fn GetIpAddrTable(table: *mut IpAddrTable, size: *mut u32, order: bool) -> u32;
    fn GetAdaptersInfo(list: *mut IpAdapterInfo, size: *mut u32) -> u32;
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not find the default IP route")]
    DefaultRouteMissing,
    #[error("could not find the default network interface")]
    DefaultInterfaceMissing,
    #[error("could not identify the default network interface")]
    DefaultInterfaceUnidentified,
    #[error("could not determine the IP address of the default network interface")]
    DefaultInterfaceNoIPAddr,
    #[error("could not determine the MAC address of the default network interface")]
    DefaultInterfaceNoMACAddr,
}

#[derive(Debug)]
pub struct NIC {
    pub guid: String,
    pub gateway: ipv4::Addr,
    pub address: ipv4::Addr,
    pub phy_address: ethernet::Addr,
}

pub fn default_nic() -> Result<NIC, error::Error> {
    let table = VLS::new(|ptr, size| GetIpForwardTable(ptr, size, false))?;
    let entry: &IpForwardRow = table
        .entries()
        .iter()
        .find(|r| r.dest == ipv4::Addr([0, 0, 0, 0]))
        .ok_or(Error::DefaultRouteMissing)?;

    let ifaces = VLS::new(|ptr, size| GetInterfaceInfo(ptr, size))?;
    let iface: &IpAdapterIndexMap = ifaces
        .adapters()
        .iter()
        .find(|r| r.index == entry.if_index)
        .ok_or(Error::DefaultInterfaceMissing)?;

    let addr_rows = VLS::new(|ptr, size| GetIpAddrTable(ptr, size, false))?;
    let address = addr_rows
        .entries()
        .iter()
        .find(|r| r.index == entry.if_index)
        .ok_or(Error::DefaultInterfaceNoIPAddr)?
        .addr;

    let mut adapter_list_head = VLS::new(|ptr, size| GetAdaptersInfo(ptr, size))?;
    let mut current = std::ptr::NonNull::new(&mut *adapter_list_head);
    let mut phy_address = None;
    loop {
        if let Some(adapter) = current {
            let adapter = unsafe { adapter.as_ref() };
            if adapter.address_length == 6 && adapter.index == entry.if_index {
                phy_address = Some(adapter.address);
                break;
            }
            current = adapter.next;
        } else {
            break;
        }
    }
    let phy_address = phy_address.ok_or(Error::DefaultInterfaceNoMACAddr)?;

    let name = iface.name.to_string();
    let guid_start = name.find("{").ok_or(Error::DefaultInterfaceUnidentified)?;
    let guid = &name[guid_start..];
    Ok(NIC {
        guid: guid.to_string(),
        address,
        phy_address,
        gateway: entry.next_hop,
    })
}

#[repr(C)]
#[derive(CustomDebug)]
pub struct IpForwardRow {
    dest: ipv4::Addr,
    mask: ipv4::Addr,
    policy: u32,
    next_hop: ipv4::Addr,
    if_index: u32,

    #[debug(skip)]
    _other_fields: [u32; 9],
}

#[repr(C)]
#[derive(Debug)]
pub struct IpForwardTable {
    num_entries: u32,
    entries: [IpForwardRow; 1],
}

impl IpForwardTable {
    fn entries(&self) -> &[IpForwardRow] {
        unsafe { slice::from_raw_parts(&self.entries[0], self.num_entries as usize) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IpInterfaceInfo {
    num_adapters: u32,
    adapter: [IpAdapterIndexMap; 1],
}

impl IpInterfaceInfo {
    pub fn adapters(&self) -> &[IpAdapterIndexMap] {
        unsafe { slice::from_raw_parts(&self.adapter[0], self.num_adapters as usize) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IpAdapterIndexMap {
    pub index: u32,
    pub name: IpAdapterName,
}

pub struct IpAdapterName([u16; 128]);

impl fmt::Display for IpAdapterName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // we assume Windows gave us valid UTF-16
        let s = String::from_utf16_lossy(&self.0[..]);
        // since the name is fixed-size at 128, we want
        // to trim any extra null WCHAR(s) at the end.
        write!(f, "{}", s.trim_end_matches("\0"))
    }
}

impl fmt::Debug for IpAdapterName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[repr(C)]
#[derive(CustomDebug)]
pub struct IpAddrRow {
    pub addr: ipv4::Addr,
    pub index: u32,
    pub mask: ipv4::Addr,
    pub bcast_addr: ipv4::Addr,
    pub reasm_size: u32,

    #[debug(skip)]
    unused1: u16,
    #[debug(skip)]
    unused2: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct IpAddrTable {
    num_entries: u32,
    entries: [IpAddrRow; 1],
}

impl IpAddrTable {
    fn entries(&self) -> &[IpAddrRow] {
        unsafe { slice::from_raw_parts(&self.entries[0], self.num_entries as usize) }
    }
}

const MAX_ADAPTER_NAME_LENGTH: usize = 256;
const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;

#[repr(C)]
#[derive(CustomDebug)]
pub struct IpAdapterInfo {
    pub next: Option<std::ptr::NonNull<IpAdapterInfo>>,
    pub combo_index: u32,

    #[debug(skip)]
    pub adapter_name: [u8; MAX_ADAPTER_NAME_LENGTH + 4],
    #[debug(skip)]
    pub description: [u8; MAX_ADAPTER_DESCRIPTION_LENGTH + 4],

    pub address_length: u32,
    pub address: ethernet::Addr,
    pub address_rest: u16,
    pub index: u32,
    pub typ: u32,
    // ignore rest of fields
}