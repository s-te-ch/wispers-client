#!/usr/bin/env python3
"""Example: register, activate, and ping a peer using wispers-connect.

Compatible with `wconnect serve` and `wconnect ping`. Uses the same wire
protocol:
  - QUIC: send "PING\n", expect "PONG\n"
  - UDP:  send "ping",   expect "pong"

Usage:
    # Node A (first node — registers, serves, prints activation code):
    python ping.py --storage /tmp/node-a --token <registration-token>

    # Node B (second node — registers, activates with code from A, pings A):
    python ping.py --storage /tmp/node-b --token <registration-token> \
        --activate <code-from-A> --ping <node-A-number>

    # You can also ping a node running `wconnect serve`:
    python ping.py --storage /tmp/node-b --ping <node-number>

    # Or have `wconnect ping` talk to a node running this script:
    wconnect ping <node-number>

Both nodes must keep running for the ping to succeed. Node A runs a serving
session in the background so it can endorse B and accept incoming connections.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time

from wispers_connect import (
    Node,
    NodeState,
    NodeStorage,
    ServingSession,
)


def print_group(node: Node) -> None:
    info = node.group_info()
    print(f"  Group state: {info.state.name}")
    for n in info.nodes:
        tag = " (self)" if n.is_self else ""
        print(f"  Node {n.node_number}: {n.name or '(unnamed)'} — {n.activation_status.name}{tag}")


def serve_in_background(session: ServingSession) -> threading.Thread:
    """Run the serving session event loop in a daemon thread."""
    t = threading.Thread(target=session.run, daemon=True)
    t.start()
    return t


def handle_quic_stream(conn, stream) -> None:  # type: ignore[no-untyped-def]
    """Handle one incoming QUIC stream using the wconnect protocol."""
    try:
        data = stream.read()
        line = data.split(b"\n", 1)[0]

        if line == b"PING":
            print(f"  Received PING, sending PONG")
            stream.write(b"PONG\n")
            stream.finish()
        else:
            print(f"  Unknown command: {line!r}")
    except Exception as e:
        print(f"  Stream error: {e}")
    finally:
        stream.close()
        conn.close()


def handle_udp_connection(conn) -> None:  # type: ignore[no-untyped-def]
    """Handle an incoming UDP connection using the wconnect protocol."""
    try:
        while True:
            data = conn.recv()
            if data == b"ping":
                print(f"  Received ping, sending pong")
                conn.send(b"pong")
            else:
                print(f"  Received {len(data)} bytes")
    except Exception as e:
        print(f"  UDP connection closed: {e}")


def accept_loop(session: ServingSession) -> None:
    """Accept incoming P2P connections and handle them."""
    if session.incoming is None:
        return

    def accept_quic() -> None:
        assert session.incoming is not None
        while True:
            try:
                conn = session.incoming.accept_quic()
                stream = conn.accept_stream()
                threading.Thread(
                    target=handle_quic_stream, args=(conn, stream), daemon=True,
                ).start()
            except Exception:
                break

    def accept_udp() -> None:
        assert session.incoming is not None
        while True:
            try:
                conn = session.incoming.accept_udp()
                threading.Thread(
                    target=handle_udp_connection, args=(conn,), daemon=True,
                ).start()
            except Exception:
                break

    threading.Thread(target=accept_quic, daemon=True).start()
    threading.Thread(target=accept_udp, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="wispers-connect ping example")
    parser.add_argument("--storage", required=True, help="Directory for node storage")
    parser.add_argument("--token", help="Registration token (needed on first run)")
    parser.add_argument("--hub", help="Override hub address (for staging/testing)")
    parser.add_argument("--activate", metavar="CODE", help="Activation code from an endorser")
    parser.add_argument("--ping", metavar="NODE_NUM", type=int, help="Peer node number to ping")
    parser.add_argument("--udp", action="store_true", help="Use UDP instead of QUIC for ping")
    args = parser.parse_args()

    # --- Init ---
    storage = NodeStorage.with_file_storage(args.storage)
    if args.hub:
        storage.override_hub_addr(args.hub)

    node, state = storage.restore_or_init()
    print(f"Node state: {state.name}")

    # --- Register ---
    if state == NodeState.PENDING:
        if not args.token:
            sys.exit("Node is PENDING — pass --token to register.")
        print("Registering...")
        node.register(args.token)
        print(f"Registered! State: {node.state.name}")

    reg = storage.read_registration()
    print(f"Node number: {reg.node_number}, group: {reg.connectivity_group_id}")

    # --- Start serving (needed for activation and ping) ---
    print("Starting serving session...")
    session = node.start_serving()
    serve_in_background(session)
    accept_loop(session)

    # --- Activate ---
    if node.state == NodeState.REGISTERED:
        if args.activate:
            print(f"Activating with code: {args.activate}")
            node.activate(args.activate)
            print(f"Activated! State: {node.state.name}")
        else:
            # We're the endorser — print a code for the other node.
            code = session.generate_activation_code()
            print(f"\nActivation code for a new peer:\n  {code}\n")
            print("Waiting for peer to activate (Ctrl-C to quit)...")
            try:
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                pass
            session.shutdown()
            session.close()
            node.close()
            storage.close()
            return

    # --- Group info ---
    print_group(node)

    # --- Ping ---
    if args.ping is not None:
        if node.state != NodeState.ACTIVATED:
            sys.exit("Must be ACTIVATED to ping a peer.")

        peer = args.ping
        transport = "UDP" if args.udp else "QUIC"
        print(f"\nPinging node {peer} via {transport}...")

        start = time.monotonic()

        if args.udp:
            conn = node.connect_udp(peer)
            connect_time = time.monotonic() - start
            print(f"  Connected in {connect_time:.3f}s")

            conn.send(b"ping")
            pong_start = time.monotonic()
            reply = conn.recv()
            rtt = time.monotonic() - pong_start

            if reply == b"pong":
                print(f"  Pong received in {rtt:.3f}s")
            else:
                print(f"  Unexpected response: {reply!r}")
            conn.close()
        else:
            conn = node.connect_quic(peer)
            connect_time = time.monotonic() - start
            print(f"  Connected in {connect_time:.3f}s")

            stream = conn.open_stream()
            stream.write(b"PING\n")
            stream.finish()

            pong_start = time.monotonic()
            reply = stream.read()
            rtt = time.monotonic() - pong_start

            if reply == b"PONG\n":
                print(f"  Pong received in {rtt:.3f}s")
            else:
                print(f"  Unexpected response: {reply!r}")
            stream.close()
            conn.close()

        print(f"Ping successful! Total time: {time.monotonic() - start:.3f}s")
    else:
        print("\nServing (Ctrl-C to quit)...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    session.shutdown()
    session.close()
    node.close()
    storage.close()


if __name__ == "__main__":
    main()
