//! Network module for mDNS operations.
//!
//! Handles mDNS daemon initialization, service registration and discovery.
//! Messages are disguised as a printer service on the local network.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;

/// mDNS service type (_printer._tcp.local.)
const SERVICE_TYPE: &str = "_printer._tcp.local.";
/// mDNS instance name (printer model)
const INSTANCE_NAME: &str = "HP_LaserJet_Pro_M402";
/// mDNS host name
const HOST_NAME: &str = "HP-M402.local.";
/// mDNS port number
const PORT: u16 = 9100;

/// Create and initialize mDNS daemon
///
/// Sets up the mDNS service daemon for service registration and discovery.
///
/// # Returns
/// * `Ok(ServiceDaemon)` if initialization succeeds
/// * `Err(String)` if initialization fails
///
/// # Example
/// ```ignore
/// let mdns = create_mdns_daemon()?;
/// ```
pub fn create_mdns_daemon() -> Result<ServiceDaemon, String> {
    ServiceDaemon::new().map_err(|e| format!("mDNS creation error: {}", e))
}

/// Get the local IPv4 address
///
/// Scans network interfaces and returns the first non-loopback,
/// non-docker IPv4 address.
///
/// # Returns
/// IPv4 address as string (defaults to "127.0.0.1" if not found)
pub fn get_local_ip() -> String {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            for iface in interfaces {
                if !iface.name.starts_with("lo") && !iface.name.contains("docker") {
                    if let std::net::IpAddr::V4(addr) = iface.ip() {
                        return addr.to_string();
                    }
                }
            }
            "127.0.0.1".to_string()
        }
        Err(_) => "127.0.0.1".to_string(),
    }
}

/// Register and send packet via mDNS
///
/// Creates an mDNS service with the encrypted payload in the TXT record.
/// The packet is disguised as a printer service announcement.
///
/// # Arguments
/// * `mdns` - mDNS daemon instance
/// * `hex_payload` - HEX-encoded encrypted packet
///
/// # Returns
/// * `Ok(())` if registration succeeds
/// * `Err(String)` if registration fails
///
/// # Example
/// ```ignore
/// let mdns = create_mdns_daemon()?;
/// send_packet(&mdns, "48656c6c6f")?;
/// ```
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<(), String> {
    let mut txt_properties = HashMap::new();
    txt_properties.insert("note".to_string(), "Office_Room_201".to_string());
    txt_properties.insert("payload".to_string(), hex_payload.to_string());

    let local_ip = get_local_ip();

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        INSTANCE_NAME,
        HOST_NAME,
        &local_ip,
        PORT,
        txt_properties,
    )
    .map_err(|e| format!("Service creation error: {}", e))?;

    mdns.register(service_info)
        .map_err(|e| format!("Service registration error: {}", e))?;

    println!("[+] Service registered at {}:{}", local_ip, PORT);
    Ok(())
}

/// Listen for and process packets from the network
///
/// Browses for mDNS printer services and calls the callback function
/// for each discovered payload.
///
/// # Arguments
/// * `mdns` - mDNS daemon instance
/// * `callback` - Function to call for each payload (HEX string)
///
/// # Returns
/// * `Ok(())` if listening starts successfully
/// * `Err(String)` if error occurs
///
/// # Example
/// ```ignore
/// let mdns = create_mdns_daemon()?;
/// listen_packets(&mdns, |payload| {
///     println!("Received: {}", payload);
///     Ok(())
/// })?;
/// ```
pub fn listen_packets<F>(mdns: &ServiceDaemon, mut callback: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let receiver = mdns
        .browse(SERVICE_TYPE)
        .map_err(|e| format!("Browse error: {}", e))?;

    let mut processed_payloads = std::collections::HashSet::new();

    println!("[*] Listening for {} ...", SERVICE_TYPE);

    while let Ok(event) = receiver.recv() {
        match event {
            ServiceEvent::ServiceFound(fullname, _) => {
                println!("[*] Service found: {}", fullname);
            }
            ServiceEvent::ServiceResolved(info) => {
                println!("[+] Service resolved: {}", info.get_fullname());

                if let Some(payload_hex) = info.get_property_val_str("payload") {
                    if processed_payloads.contains(payload_hex) {
                        continue;
                    }
                    processed_payloads.insert(payload_hex.to_string());

                    if let Err(e) = callback(payload_hex) {
                        println!("[!] Processing error: {}", e);
                    }
                }
            }
            ServiceEvent::ServiceRemoved(fullname, _) => {
                println!("[-] Service removed: {}", fullname);
            }
            _ => {}
        }
    }

    Ok(())
}
