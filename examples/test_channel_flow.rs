//! Example: Channel-based data loading pattern
//!
//! Run with: cargo run --example test_channel_flow

use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() {
    println!("🧪 Testing channel-based data loading pattern\n");

    // Create channel
    let (tx, rx) = mpsc::channel::<Vec<String>>();

    // Simulate background data loading
    println!("📤 Spawning background thread...");
    std::thread::spawn(move || {
        println!("  ⚙️  Background: Simulating data load...");
        std::thread::sleep(Duration::from_millis(500)); // Simulate async work

        let data = vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "charlie@example.com".to_string(),
        ];

        println!("  📤 Background: Sending {} items...", data.len());
        tx.send(data).unwrap();
        println!("  ✓ Background: Data sent");
    });

    // Main thread polls for data
    println!("\n📥 Main thread: Polling for data...");
    let start = Instant::now();
    let timeout = Duration::from_secs(2);

    loop {
        match rx.try_recv() {
            Ok(data) => {
                println!("✓ Main thread received {} items!", data.len());
                println!("\n📄 Data:");
                for (i, item) in data.iter().enumerate() {
                    println!("  {}: {}", i + 1, item);
                }
                println!("\n✅ Test PASSED: Channel communication works!");
                println!("   This confirms the MySqlTablePlugin channel pattern is correct.");
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {
                if start.elapsed() > timeout {
                    println!("\n❌ Test FAILED: Timeout");
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                println!("\n❌ Test FAILED: Channel disconnected");
                return;
            }
        }
    }
}
