use mdns_covert::crypto::{chacha20_decrypt, chacha20_encrypt, hex_decode, hex_encode};
use mdns_covert::network::{create_mdns_daemon, listen_packets, send_packet};
use mdns_covert::protocol::{MessageType, Packet};

use clap::{Parser, Subcommand};
use std::sync::mpsc;
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
    Send {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    Listen {
        #[arg(short, long)]
        key: String,
    },
    Test {
        #[arg(short, long, default_value = "test_key")]
        key: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Send { key, message } => send_command(key, message)?,
        Commands::Listen { key } => listen_command(key)?,
        Commands::Test { key } => test_command(key)?,
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

    println!("[*] ChaCha20-Poly1305 encryption");
    let encrypted =
        chacha20_encrypt(&packet_data, key).map_err(|e| format!("Encryption error: {}", e))?;

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
    println!("[*] Encryption key: [hidden]");

    let mdns = create_mdns_daemon()?;

    listen_packets(&mdns, |hex_payload: &str| {
        println!(
            "\n[*] Packet received (HEX: {}...)",
            &hex_payload[..std::cmp::min(30, hex_payload.len())]
        );

        let encrypted = hex_decode(hex_payload).map_err(|e| format!("HEX decode error: {}", e))?;

        let packet_data =
            chacha20_decrypt(&encrypted, key).map_err(|e| format!("Decryption error: {}", e))?;

        let packet = Packet::deserialize(&packet_data)
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

fn test_command(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== mDNS Covert Channel Self-Test ===\n");

    let (tx, rx) = mpsc::channel::<String>();

    let key_clone = key.to_string();
    let _recv_handle = thread::spawn(move || {
        let mdns = create_mdns_daemon().map_err(|e| e.to_string())?;
        listen_packets(&mdns, |hex_payload: &str| {
            let encrypted =
                hex_decode(hex_payload).map_err(|e| format!("HEX decode error: {}", e))?;
            let packet_data = chacha20_decrypt(&encrypted, &key_clone)
                .map_err(|e| format!("Decryption error: {}", e))?;
            let packet = Packet::deserialize(&packet_data)
                .map_err(|e| format!("Deserialization error: {}", e))?;
            if let Ok(text) = String::from_utf8(packet.payload.clone()) {
                let _ = tx.send(text);
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    });

    println!("[*] Starting receiver...");
    thread::sleep(Duration::from_secs(2));

    let messages = vec!["Hello, World!", "Testing mDNS", "Secret message"];

    let mdns = create_mdns_daemon()?;
    let mut sent_count = 0u32;

    for (i, msg) in messages.iter().enumerate() {
        println!("[*] Sending message {}: \"{}\"", i + 1, msg);

        let packet = Packet::new(MessageType::Data, msg.as_bytes().to_vec());
        let packet_data = packet.serialize();
        let encrypted = chacha20_encrypt(&packet_data, key)?;
        let hex_payload = hex_encode(&encrypted);

        send_packet(&mdns, &hex_payload)?;
        sent_count += 1;

        thread::sleep(Duration::from_secs(3));
    }

    let mut received = Vec::new();
    while let Ok(msg) = rx.recv_timeout(Duration::from_secs(5)) {
        received.push(msg);
    }

    println!("\n=== Results ===");
    println!("Sent:     {}", sent_count);
    println!("Received: {}", received.len());

    for (i, msg) in received.iter().enumerate() {
        println!("  [{}] \"{}\"", i + 1, msg);
    }

    if received.len() == sent_count as usize {
        println!("\n[+] All messages received successfully!");
    } else {
        println!(
            "\n[!] Partial result: {}/{} messages received",
            received.len(),
            sent_count
        );
        println!("    (Some messages may still be in transit on the network)");
    }

    thread::sleep(Duration::from_secs(2));
    Ok(())
}
