#![allow(non_snake_case)]

mod vls;

use crate::{
    error::Error,
    ipv4,
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
}

pub fn default_nic_guid() -> Result<String, Error> {
    let table = VLS::new(|ptr, size| GetIpForwardTable(ptr, size, false))?;
    let entry: &IpForwardRow = table
        .entries()
        .iter()
        .find(|r| r.dest == ipv4::Addr([0, 0, 0, 0]))
        .expect("should have default interface");

    let ifaces = VLS::new(|ptr, size| GetInterfaceInfo(ptr, size))?;
    let iface: &IpAdapterIndexMap = ifaces
        .adapters()
        .iter()
        .find(|r| r.index == entry.if_index)
        .expect("default interface should exist");

    let name = iface.name.to_string();
    let guid_start = name.find("{").expect("interface name should have a guid");
    let guid = &name[guid_start..];

    Ok(guid.to_string())
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