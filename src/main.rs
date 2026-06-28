mod crypto;
mod network;
mod protocol;

use clap::{Parser, Subcommand};
use crypto::{chacha20_decrypt, chacha20_encrypt, hex_decode, hex_encode};
use network::{create_mdns_daemon, listen_packets, send_packet};
use protocol::{MessageType, Packet};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "mDNS Covert Channel")]
#[command(about = "Covert message transmission via mDNS/ZeroConf TXT records", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a message
    Send {
        #[arg(short, long, default_value = "secret_key")]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    /// Listen for messages on the network
    Listen {
        #[arg(short, long, default_value = "secret_key")]
        key: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Send { key, message } => send_command(key, message)?,
        Commands::Listen { key } => listen_command(key)?,
    }

    Ok(())
}

fn send_command(key: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Preparing message...");

    let message_bytes = message.as_bytes().to_vec();

    let mut packet = Packet::new(MessageType::Data, message_bytes);
    packet.sequence = 0;

    let packet_data = packet.serialize();
    println!("[*] Packet size: {} bytes", packet_data.len());

    println!("[*] ChaCha20-Poly1305 encryption with key: {}", key);
    let encrypted = chacha20_encrypt(&packet_data, key)?;

    let hex_payload = hex_encode(&encrypted);
    println!(
        "[*] HEX payload: {}",
        &hex_payload[..std::cmp::min(50, hex_payload.len())]
    );
    println!("    (total {} characters)", hex_payload.len());

    let mdns = create_mdns_daemon()?;
    println!("[*] mDNS initialized");

    send_packet(&mdns, &hex_payload)?;

    println!("\n[+] Message sent!");
    println!("    ID: {}", packet.message_id);
    println!("    Timestamp: {}", packet.timestamp);
    println!("    Original text: {}", message);

    println!("\n[*] Press Ctrl+C to exit");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn listen_command(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Listener initialized...");
    println!("[*] Encryption key: {}", key);

    let mdns = create_mdns_daemon()?;

    listen_packets(&mdns, |hex_payload: &str| {
        println!(
            "\n[*] Packet received (HEX: {}...)",
            &hex_payload[..std::cmp::min(30, hex_payload.len())]
        );

        let encrypted = hex_decode(hex_payload).map_err(|e| format!("HEX decode error: {}", e))?;

        let packet_data = chacha20_decrypt(&encrypted, key)?;

        let packet = protocol::Packet::deserialize(&packet_data)
            .map_err(|e| format!("Deserialization error: {}", e))?;

        match String::from_utf8(packet.payload.clone()) {
            Ok(text) => {
                println!("[+] Message from {:?}:", packet.msg_type);
                println!("    ID: {}", packet.message_id);
                println!("    Timestamp: {}", packet.timestamp);
                println!("    Size: {} bytes", packet.payload.len());
                println!("    {}", text);
            }
            Err(_) => {
                println!("[!] Payload is not text");
                println!(
                    "    Bytes: {:?}",
                    &packet.payload[..std::cmp::min(20, packet.payload.len())]
                );
            }
        }

        Ok(())
    })?;

    Ok(())
}
