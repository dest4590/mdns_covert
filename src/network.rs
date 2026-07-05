//! Network module for mDNS operations.
//!
//! Handles mDNS daemon initialization, service registration and discovery.
//! Messages are disguised as random device services on the local network.
//! Supports printers, TVs, phones, and speakers for varied obfuscation.

use crate::db::{self, DeviceProfile};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::seq::IndexedRandom;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Replay detector for deduplicating received payloads.
///
/// Maintains a time-windowed set of seen payload hashes.
/// Expired entries are automatically pruned on each call.
pub struct ReplayDetector {
    seen: HashSet<String>,
    timestamps: HashMap<String, Instant>,
    window: Duration,
}

impl ReplayDetector {
    pub fn new(window: Duration) -> Self {
        ReplayDetector {
            seen: HashSet::new(),
            timestamps: HashMap::new(),
            window,
        }
    }

    pub fn is_new(&mut self, payload_hex: &str) -> bool {
        self.prune_expired();
        if self.seen.contains(payload_hex) {
            return false;
        }
        self.seen.insert(payload_hex.to_string());
        self.timestamps
            .insert(payload_hex.to_string(), Instant::now());
        true
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .timestamps
            .iter()
            .filter(|(_, time)| now.duration_since(**time) >= self.window)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.seen.remove(&key);
            self.timestamps.remove(&key);
        }
    }
}

fn get_random_device() -> DeviceProfile {
    let mut rng = rand::rng();
    db::DEVICE_PROFILES
        .choose(&mut rng)
        .unwrap_or(&db::DEVICE_PROFILES[0])
        .clone()
}

fn get_random_location() -> &'static str {
    let mut rng = rand::rng();
    db::LOCATION_VARIATIONS
        .choose(&mut rng)
        .unwrap_or(&"Main Office")
}

pub fn create_mdns_daemon() -> Result<ServiceDaemon, String> {
    ServiceDaemon::new().map_err(|e| format!("mDNS creation error: {}", e))
}

pub fn get_local_ip() -> String {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            for iface in interfaces {
                if !iface.name.starts_with("lo")
                    && !iface.name.contains("docker")
                    && let std::net::IpAddr::V4(addr) = iface.ip()
                {
                    return addr.to_string();
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
/// The packet is disguised as a randomized device service announcement
/// (printer, TV, phone, speaker) for better obfuscation.
///
/// # Returns
/// * `Ok(String)` - The service instance name for later deregistration
pub fn send_packet(mdns: &ServiceDaemon, hex_payload: &str) -> Result<String, String> {
    let device = get_random_device();

    let mut txt_properties = HashMap::new();
    txt_properties.insert("note".to_string(), get_random_location().to_string());
    txt_properties.insert("payload".to_string(), hex_payload.to_string());
    txt_properties.insert("vendor".to_string(), device.vendor.to_string());
    txt_properties.insert("model".to_string(), device.model.to_string());

    let local_ip = get_local_ip();
    let instance_name = device.instance_name();
    let host_name = device.host_name();

    let service_info = ServiceInfo::new(
        device.service_type,
        &instance_name,
        &host_name,
        &local_ip,
        device.port,
        txt_properties,
    )
    .map_err(|e| format!("Service creation error: {}", e))?;

    mdns.register(service_info)
        .map_err(|e| format!("Service registration error: {}", e))?;

    println!("[+] Registered as {}", device.full_service_name());
    println!("    Service: {}", device.service_type);
    println!("    Vendor:  {}", device.vendor);
    println!("    Model:   {}", device.model);
    println!("    Address: {}:{}", local_ip, device.port);

    Ok(device.full_service_name())
}

pub fn deregister_service(mdns: &ServiceDaemon, service_name: &str) -> Result<(), String> {
    mdns.unregister(service_name)
        .map_err(|e| format!("Service deregistration error: {}", e))?;
    Ok(())
}

/// Listen for and process packets from the network.
///
/// Browses all device service types (printer, TV, phone) and calls the
/// callback function for each discovered payload.
pub fn listen_packets<F>(mdns: &ServiceDaemon, mut callback: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    // Browse all known service types
    let service_types = [
        "_printer._tcp.local.",
        "_airplay._tcp.local.",
        "_hap._tcp.local.",
    ];

    let mut receivers = Vec::new();
    for st in &service_types {
        match mdns.browse(st) {
            Ok(receiver) => {
                println!("[*] Browsing {} ...", st);
                receivers.push(receiver);
            }
            Err(e) => {
                println!("[!] Failed to browse {}: {}", st, e);
            }
        }
    }

    if receivers.is_empty() {
        return Err("No service types could be browsed".to_string());
    }

    let mut replay_detector = ReplayDetector::new(Duration::from_secs(300));

    // Round-robin through receivers
    loop {
        for receiver in &receivers {
            if let Ok(event) = receiver.try_recv() {
                match event {
                    ServiceEvent::ServiceFound(fullname, _) => {
                        println!("[*] Service found: {}", fullname);
                    }
                    ServiceEvent::ServiceResolved(info) => {
                        println!("[+] Service resolved: {}", info.get_fullname());

                        if let Some(payload_hex) = info.get_property_val_str("payload") {
                            if !replay_detector.is_new(payload_hex) {
                                continue;
                            }

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
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_detector_new_payload() {
        let mut detector = ReplayDetector::new(Duration::from_secs(60));
        assert!(detector.is_new("deadbeef"));
    }

    #[test]
    fn test_replay_detector_duplicate_payload() {
        let mut detector = ReplayDetector::new(Duration::from_secs(60));
        assert!(detector.is_new("deadbeef"));
        assert!(!detector.is_new("deadbeef"));
    }

    #[test]
    fn test_replay_detector_different_payloads() {
        let mut detector = ReplayDetector::new(Duration::from_secs(60));
        assert!(detector.is_new("deadbeef"));
        assert!(detector.is_new("cafebabe"));
        assert!(!detector.is_new("deadbeef"));
        assert!(!detector.is_new("cafebabe"));
    }

    #[test]
    fn test_replay_detector_expired_payload() {
        let mut detector = ReplayDetector::new(Duration::from_millis(1));
        assert!(detector.is_new("deadbeef"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(detector.is_new("deadbeef"));
    }

    #[test]
    fn test_replay_detector_prune_cleanup() {
        let mut detector = ReplayDetector::new(Duration::from_millis(1));
        detector.is_new("aaa");
        detector.is_new("bbb");
        std::thread::sleep(Duration::from_millis(5));
        detector.is_new("ccc");
        assert!(!detector.seen.contains("aaa"));
        assert!(!detector.seen.contains("bbb"));
        assert!(detector.seen.contains("ccc"));
        assert_eq!(detector.seen.len(), 1);
    }

    #[test]
    fn test_device_profile_full_service_name() {
        let profile = DeviceProfile::new("_printer._tcp.local.", "HP", "LaserJet", 9100);
        assert_eq!(
            profile.full_service_name(),
            "HP_LaserJet._printer._tcp.local."
        );
    }

    #[test]
    fn test_device_profiles_not_empty() {
        assert!(!db::DEVICE_PROFILES.is_empty());
        assert!(db::PRINTER_PROFILES.len() > 0);
        assert!(db::TV_PROFILES.len() > 0);
        assert!(db::PHONE_PROFILES.len() > 0);
    }

    #[test]
    fn test_location_variations_not_empty() {
        assert!(!db::LOCATION_VARIATIONS.is_empty());
    }

    #[test]
    fn test_get_random_device_returns_valid() {
        let device = get_random_device();
        assert!(!device.vendor.is_empty());
        assert!(!device.model.is_empty());
        assert!(!device.service_type.is_empty());
    }

    #[test]
    fn test_get_random_location_returns_valid() {
        let location = get_random_location();
        assert!(!location.is_empty());
    }
}
