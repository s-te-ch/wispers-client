//! P2P client operations - ping and forward commands.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wispers_connect::{Node, NodeState};

pub async fn ping(
    hub_override: Option<&str>,
    profile: &str,
    target_node: i32,
    use_quic: bool,
) -> Result<()> {
    let storage = super::get_storage(hub_override, profile)?;
    let node = super::load_node(&storage).await?;

    match node.state() {
        NodeState::Pending => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeState::Registered => {
            anyhow::bail!("Not activated. Use 'wconnect activate <activation_code>' first.");
        }
        NodeState::Activated => {}
    }

    let our_node = node.node_number().unwrap();
    if target_node == our_node {
        anyhow::bail!("Cannot ping yourself (node {our_node}).");
    }

    let transport = if use_quic { "QUIC" } else { "UDP" };
    println!("Pinging node {target_node} via {transport}...");

    let start = std::time::Instant::now();

    if use_quic {
        ping_quic(&node, target_node, start).await
    } else {
        ping_udp(&node, target_node, start).await
    }
}

async fn ping_udp(node: &Node, target_node: i32, start: std::time::Instant) -> Result<()> {
    let conn = node
        .connect_udp(target_node)
        .await
        .context("failed to connect")?;

    let connect_time = start.elapsed();
    println!("  Connected in {connect_time:?}");

    conn.send(b"ping").context("failed to send ping")?;

    let pong_start = std::time::Instant::now();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
        .await
        .context("timeout waiting for pong")?
        .context("failed to receive pong")?;

    let rtt = pong_start.elapsed();

    if response == b"pong" {
        println!("  Pong received in {rtt:?}");
        println!("Ping successful! Total time: {:?}", start.elapsed());
    } else {
        println!(
            "  Unexpected response: {:?}",
            String::from_utf8_lossy(&response)
        );
    }

    Ok(())
}

async fn ping_quic(node: &Node, target_node: i32, start: std::time::Instant) -> Result<()> {
    let conn = node
        .connect_quic(target_node)
        .await
        .context("failed to connect")?;

    let connect_time = start.elapsed();
    println!("  Connected in {connect_time:?}");

    let stream_start = std::time::Instant::now();
    let stream = conn.open_stream().await.context("failed to open stream")?;
    let stream_time = stream_start.elapsed();
    println!("  Stream opened in {stream_time:?}");

    stream
        .write_all(b"PING\n")
        .await
        .context("failed to send PING")?;
    stream.finish().await.context("failed to finish stream")?;

    let pong_start = std::time::Instant::now();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("timeout waiting for PONG")?
        .context("failed to receive PONG")?;

    let rtt = pong_start.elapsed();
    let response = &buf[..n];

    if response == b"PONG\n" {
        println!("  Pong received in {rtt:?}");
        println!("Ping successful! Total time: {:?}", start.elapsed());
    } else {
        println!(
            "  Unexpected response: {:?}",
            String::from_utf8_lossy(response)
        );
    }

    Ok(())
}

pub async fn forward(
    hub_override: Option<&str>,
    profile: &str,
    local_port: u16,
    target_node: i32,
    remote_port: u16,
) -> Result<()> {
    if local_port == 0 {
        anyhow::bail!("Local port cannot be 0");
    }
    if remote_port == 0 {
        anyhow::bail!("Remote port cannot be 0");
    }

    let storage = super::get_storage(hub_override, profile)?;
    let node = super::load_node(&storage).await?;

    match node.state() {
        NodeState::Pending => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeState::Registered => {
            anyhow::bail!("Not activated. Use 'wconnect activate <activation_code>' first.");
        }
        NodeState::Activated => {}
    }

    let our_node = node.node_number().unwrap();
    if target_node == our_node {
        anyhow::bail!("Cannot forward to yourself (node {our_node}).");
    }

    println!(
        "Forwarding localhost:{local_port} -> node {target_node}:localhost:{remote_port}"
    );

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{local_port}"))
        .await
        .context(format!("failed to bind to port {local_port}"))?;

    println!("Listening on 127.0.0.1:{local_port}");

    print!("Connecting to node {target_node}...");
    std::io::Write::flush(&mut std::io::stdout())?;

    let quic_conn = node
        .connect_quic(target_node)
        .await
        .context("failed to connect to target node")?;

    println!(" connected");
    println!("Press Ctrl+C to stop");

    let quic_conn = Arc::new(quic_conn);
    let connection_count = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (tcp_stream, peer_addr) = result.context("failed to accept connection")?;

                let count = connection_count.fetch_add(1, Ordering::Relaxed) + 1;
                println!("[{count}] Accepted connection from {peer_addr}");

                let quic_conn = Arc::clone(&quic_conn);
                tokio::spawn(async move {
                    if let Err(e) = Box::pin(handle_forward_connection(tcp_stream, quic_conn, remote_port)).await {
                        eprintln!("[{count}] Forward error: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                let total = connection_count.load(Ordering::Relaxed);
                println!("\nStopping. Total connections forwarded: {total}");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_forward_connection(
    tcp_stream: tokio::net::TcpStream,
    quic_conn: Arc<wispers_connect::QuicConnection>,
    remote_port: u16,
) -> Result<()> {
    let stream = quic_conn
        .open_stream()
        .await
        .context("failed to open QUIC stream")?;

    let cmd = format!("FORWARD {remote_port}\n");
    stream
        .write_all(cmd.as_bytes())
        .await
        .context("failed to send FORWARD command")?;

    let mut buf = [0u8; 256];
    let n = stream
        .read(&mut buf)
        .await
        .context("failed to read response")?;

    let response = String::from_utf8_lossy(&buf[..n]);
    let response = response.trim();

    if response == "OK" {
        let stream_id = stream.id();
        println!("  Stream {stream_id} forwarding to port {remote_port}");

        let stream = Arc::new(stream);
        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        let stream_for_read = Arc::clone(&stream);
        let stream_for_write = Arc::clone(&stream);

        // TCP -> QUIC
        let tcp_to_quic = async move {
            let mut buf = [0u8; 8192];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream_for_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stream_for_write.finish().await;
        };

        // QUIC -> TCP
        let quic_to_tcp = async move {
            let mut buf = [0u8; 8192];
            loop {
                match stream_for_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tcp_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = tcp_write.shutdown().await;
        };

        tokio::join!(tcp_to_quic, quic_to_tcp);
        println!("  Stream {stream_id} closed");
        Ok(())
    } else if let Some(msg) = response.strip_prefix("ERROR ") {
        anyhow::bail!("Remote error: {msg}");
    } else {
        anyhow::bail!("Unexpected response: {response}");
    }
}
