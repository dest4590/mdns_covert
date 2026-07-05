use std::sync::LazyLock;

/// A generic device profile for mDNS service obfuscation.
#[derive(Clone)]
pub struct DeviceProfile {
    pub service_type: &'static str,
    pub vendor: &'static str,
    pub model: &'static str,
    pub port: u16,
}

impl DeviceProfile {
    pub const fn new(
        service_type: &'static str,
        vendor: &'static str,
        model: &'static str,
        port: u16,
    ) -> Self {
        Self {
            service_type,
            vendor,
            model,
            port,
        }
    }

    pub fn instance_name(&self) -> String {
        format!(
            "{}_{}",
            self.vendor.replace(' ', "_"),
            self.model.replace(' ', "_")
        )
    }

    pub fn host_name(&self) -> String {
        let code = self
            .model
            .replace(' ', "")
            .chars()
            .take(6)
            .collect::<String>();
        let prefix = self.vendor.chars().next().unwrap_or('D');
        format!("{}-{}.local.", prefix, code)
    }

    pub fn full_service_name(&self) -> String {
        format!("{}.{}", self.instance_name(), self.service_type)
    }
}

pub static DEVICE_PROFILES: LazyLock<Vec<DeviceProfile>> = LazyLock::new(|| {
    let mut v = Vec::new();
    v.extend_from_slice(&PRINTER_PROFILES);
    v.extend_from_slice(&TV_PROFILES);
    v.extend_from_slice(&PHONE_PROFILES);
    v
});

//  Printers
#[rustfmt::skip]
pub static PRINTER_PROFILES: LazyLock<Vec<DeviceProfile>> = LazyLock::new(|| {
    vec![
        DeviceProfile::new("_printer._tcp.local.", "HP", "LaserJet Pro M402", 9100),
        DeviceProfile::new("_printer._tcp.local.", "HP", "LaserJet Enterprise M506", 9100),
        DeviceProfile::new("_printer._tcp.local.", "HP", "OfficeJet Pro 8025", 9100),
        DeviceProfile::new("_printer._tcp.local.", "HP", "Color LaserJet Pro M454", 9100),
        DeviceProfile::new("_printer._tcp.local.", "HP", "PageWide Pro 777", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Canon", "imageRUNNER 2520", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Canon", "imageRUNNER ADVANCE C3500", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Canon", "LBP664Cx", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Xerox", "VersaLink C7025", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Xerox", "WorkCentre 5335", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Brother", "HL-L8360CDW", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Brother", "MFC-L9550CDW", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Ricoh", "MP C3004", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Ricoh", "AFICIO MP 7502", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Kyocera", "ECOSYS M8130cidn", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Kyocera", "TASKalfa 3510i", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Lexmark", "MS825", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Lexmark", "CX725", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Toshiba", "e-STUDIO 3008A", 9100),
        DeviceProfile::new("_printer._tcp.local.", "Toshiba", "e-STUDIO 2018A", 9100),
    ]
});

//  TVs
#[rustfmt::skip]
pub static TV_PROFILES: LazyLock<Vec<DeviceProfile>> = LazyLock::new(|| {
    vec![
        DeviceProfile::new("_airplay._tcp.local.", "Samsung", "QN65QN85BAF", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Samsung", "UN55TU8300FXZC", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Samsung", "QN75QN900AFXZA", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "LG", "OLED55C1PUB", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "LG", "65NANO85UPA", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "LG", "OLED65G2PUA", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Sony", "XR-65A95K", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Sony", "XBR-55X90J", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Sony", "XR-77A80K", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "TCL", "65R646", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "TCL", "55S546", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Vizio", "M65Q7-J09", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Vizio", "OLED55-H1", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Hisense", "65U8H", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Hisense", "55A6H", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Panasonic", "TX-55MZ2000", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Philips", "55OLED707", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Sharp", "4T-C55GL4000R", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Toshiba", "55UA2B63", 7000),
        DeviceProfile::new("_airplay._tcp.local.", "Insignia", "NS-55F301NA22", 7000),
    ]
});

//  Phones / Speakers
#[rustfmt::skip]
pub static PHONE_PROFILES: LazyLock<Vec<DeviceProfile>> = LazyLock::new(|| {
    vec![
        DeviceProfile::new("_hap._tcp.local.", "Apple", "iPhone 14 Pro", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Apple", "iPhone 13", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Apple", "iPhone 15", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Apple", "iPhone SE", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Samsung", "Galaxy S23 Ultra", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Samsung", "Galaxy S24", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Samsung", "Galaxy Z Fold5", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Google", "Pixel 8 Pro", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Google", "Pixel 7a", 51820),
        DeviceProfile::new("_hap._tcp.local.", "OnePlus", "12", 51820),
        DeviceProfile::new("_hap._tcp.local.", "OnePlus", "11", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Xiaomi", "14 Pro", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Xiaomi", "13T", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Sony", "Xperia 1 V", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Motorola", "Edge 40 Pro", 51820),
        DeviceProfile::new("_hap._tcp.local.", "Sonos", "One SL", 1400),
        DeviceProfile::new("_hap._tcp.local.", "Sonos", "Move 2", 1400),
        DeviceProfile::new("_hap._tcp.local.", "Sonos", "Era 300", 1400),
        DeviceProfile::new("_hap._tcp.local.", "Amazon", "Echo Dot 5th Gen", 1400),
        DeviceProfile::new("_hap._tcp.local.", "Amazon", "Echo Show 10", 1400),
    ]
});

/// Location variations for TXT record metadata
pub static LOCATION_VARIATIONS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
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
});
