# oppa
Custom implementation of [ping](https://en.wikipedia.org/wiki/Ping_(networking_utility)) written while reading [this blog series](https://fasterthanli.me/series/making-our-own-ping).  

## Platforms 
`Windows` only. There must be a packet capturing library installed, for example [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/).

## Usage
`$ oppa DEST`  

where **DEST** is an IPv4 address.

Example:   
`$ oppa 8.8.8.8`