//! Network module for mDNS operations.
//!
//! Handles mDNS daemon initialization, service registration and discovery.
//! Messages are disguised as a printer service on the local network.
//! Supports multiple printer models and randomized masking for stealth.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::seq::IndexedRandom;
use std::collections::HashMap;

/// mDNS service type (_printer._tcp.local.)
const SERVICE_TYPE: &str = "_printer._tcp.local.";

/// Realistic printer profiles for better masking
#[derive(Clone)]
pub struct PrinterProfile {
    pub vendor: &'static str,
    pub model: &'static str,
    pub instance_name: String,
    pub host_name: String,
    pub port: u16,
    pub location: &'static str,
}

impl PrinterProfile {
    /// Create a new printer profile
    fn new(
        vendor: &'static str,
        model: &'static str,
        code: &'static str,
        port: u16,
        location: &'static str,
    ) -> Self {
        let instance_name = format!("{}_{}", vendor.replace(" ", "_"), model.replace(" ", "_"));
        let host_name = format!("{}-{}.local.", vendor.chars().next().unwrap_or('H'), code);

        PrinterProfile {
            vendor,
            model,
            instance_name,
            host_name,
            port,
            location,
        }
    }
}

/// List of realistic printer profiles for obfuscation
fn get_printer_profiles() -> Vec<PrinterProfile> {
    vec![
        // HP Printers
        PrinterProfile::new("HP", "LaserJet Pro M402", "M402", 9100, "Main Office"),
        PrinterProfile::new("HP", "LaserJet Enterprise M506", "M506", 9100, "Room 301"),
        PrinterProfile::new("HP", "OfficeJet Pro 8025", "8025", 9100, "Break Room"),
        PrinterProfile::new(
            "HP",
            "Color LaserJet Pro M454",
            "M454",
            9100,
            "Design Floor",
        ),
        PrinterProfile::new("HP", "PageWide Pro 777", "777", 9100, "Floor 2"),
        // Canon
        PrinterProfile::new(
            "Canon",
            "imageRUNNER 2520",
            "IR2520",
            9100,
            "Conference Room A",
        ),
        PrinterProfile::new(
            "Canon",
            "imageRUNNER ADVANCE C3500",
            "C3500",
            9100,
            "Copy Center",
        ),
        PrinterProfile::new("Canon", "LBP664Cx", "LBP664", 9100, "Accounting"),
        // Xerox
        PrinterProfile::new("Xerox", "VersaLink C7025", "C7025", 9100, "Marketing"),
        PrinterProfile::new("Xerox", "WorkCentre 5335", "5335", 9100, "IT Department"),
        // Brother
        PrinterProfile::new("Brother", "HL-L8360CDW", "L8360", 9100, "Executive Suite"),
        PrinterProfile::new("Brother", "MFC-L9550CDW", "L9550", 9100, "Warehouse"),
        // Ricoh
        PrinterProfile::new("Ricoh", "MP C3004", "C3004", 9100, "Legal"),
        PrinterProfile::new("Ricoh", "AFICIO MP 7502", "7502", 9100, "Reception"),
        // Kyocera
        PrinterProfile::new(
            "Kyocera",
            "ECOSYS M8130cidn",
            "M8130",
            9100,
            "Finance Floor",
        ),
        PrinterProfile::new("Kyocera", "TASKalfa 3510i", "3510", 9100, "Engineering"),
        // Lexmark
        PrinterProfile::new("Lexmark", "MS825", "MS825", 9100, "HR Department"),
        PrinterProfile::new("Lexmark", "CX725", "CX725", 9100, "Floor 3"),
        // Toshiba
        PrinterProfile::new("Toshiba", "e-STUDIO 3008A", "3008A", 9100, "Logistics"),
        PrinterProfile::new("Toshiba", "e-STUDIO 2018A", "2018A", 9100, "Support Center"),
    ]
}

/// Location variations for added obfuscation
fn get_location_variations() -> Vec<&'static str> {
    vec![
        "Main Office",
        "Break Room",
        "Conference Room A",
        "Conference Room B",
        "Floor 2",
        "Floor 3",
        "Floor 4",
        "Copy Center",
        "Accounting",
        "Marketing",
        "IT Department",
        "Executive Suite",
        "Warehouse",
        "Legal",
        "Reception",
        "Finance Floor",
        "Engineering",
        "HR Department",
        "Sales Floor",
        "Support Center",
        "Room 201",
        "Room 202",
        "Room 301",
        "Room 401",
    ]
}

/// Get a random printer profile for masking
fn get_random_printer() -> PrinterProfile {
    let mut rng = rand::rng();
    let profiles: Vec<PrinterProfile> = get_printer_profiles();
    profiles
        .choose(&mut rng)
        .unwrap_or_else(|| &profiles[0])
        .clone()
}

/// Get a random location for the TXT record
fn get_random_location() -> &'static str {
    let mut rng = rand::rng();
    let locations = get_location_variations();
    *locations.choose(&mut rng).unwrap_or(&"Main Office")
}

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
/// The packet is disguised as a randomized printer service announcement
/// for better obfuscation and stealth.
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
    let printer = get_random_printer();

    let mut txt_properties = HashMap::new();
    txt_properties.insert("note".to_string(), get_random_location().to_string());
    txt_properties.insert("payload".to_string(), hex_payload.to_string());
    txt_properties.insert("vendor".to_string(), printer.vendor.to_string());
    txt_properties.insert("model".to_string(), printer.model.to_string());

    let local_ip = get_local_ip();

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &printer.instance_name,
        &printer.host_name,
        &local_ip,
        printer.port,
        txt_properties,
    )
    .map_err(|e| format!("Service creation error: {}", e))?;

    mdns.register(service_info)
        .map_err(|e| format!("Service registration error: {}", e))?;

    println!("[+] Service registered as {}", printer.instance_name);
    println!("    Vendor: {}", printer.vendor);
    println!("    Model: {}", printer.model);
    println!("    Location: {}", printer.location);
    println!("    Address: {}:{}", local_ip, printer.port);
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
