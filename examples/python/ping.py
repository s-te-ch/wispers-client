#!/usr/bin/env python3
"""Example: register, activate, serve, and ping using wispers-connect.

Compatible with `wconnect` and the C/Go examples. Uses the same wire protocol:
  - QUIC: send "PING\n", expect "PONG\n"
  - UDP:  send "ping",   expect "pong"

Usage:
    python ping.py status
    python ping.py register TOKEN
    python ping.py activate CODE
    python ping.py nodes
    python ping.py serve
    python ping.py ping NODE_NUM [--quic]

Global flags:
    --hub ADDR        Override hub address
    --storage DIR     Storage directory (default: platform config dir + wispers-connect-examples/python/)
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
import threading
import time
from pathlib import Path

from wispers_connect import (
    GroupState,
    Node,
    NodeState,
    NodeStorage,
    ServingSession,
)

# =============================================================================
# main
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="wispers-connect example (compatible with wconnect, ffi_demo, wconnect-go)",
    )
    parser.add_argument("--hub", help="Override hub address")
    parser.add_argument("--storage", help="Storage directory (default: platform config dir + wispers-connect-examples/python/)")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show current node state and registration info")

    p_reg = sub.add_parser("register", help="Register this node with a registration token")
    p_reg.add_argument("token", help="Registration token")

    p_act = sub.add_parser("activate", help="Activate using an activation code from an endorser")
    p_act.add_argument("code", help="Activation code")

    sub.add_parser("nodes", help="List nodes in the connectivity group")

    sub.add_parser("serve", help="Serve (accept connections, print activation code if needed)")

    p_ping = sub.add_parser("ping", help="Ping a peer node (UDP by default, --quic for QUIC)")
    p_ping.add_argument("node_num", type=int, help="Peer node number")
    p_ping.add_argument("--quic", action="store_true", help="Use QUIC instead of UDP")

    args = parser.parse_args()

    handlers = {
        "status": cmd_status,
        "register": cmd_register,
        "activate": cmd_activate,
        "nodes": cmd_nodes,
        "serve": cmd_serve,
        "ping": cmd_ping,
    }

    sys.exit(handlers[args.command](args))


# =============================================================================
# Commands
# =============================================================================


def cmd_status(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)
    print(f"Node state: {state.name}")

    if state != NodeState.PENDING:
        reg = storage.read_registration()
        print(f"Node number: {reg.node_number}, group: {reg.connectivity_group_id}")
        print_group(node)

    node.close()
    storage.close()
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)

    if state != NodeState.PENDING:
        print(f"Cannot register: already {state.name}")
        node.close()
        storage.close()
        return 1

    print("Registering...")
    node.register(args.token)
    print(f"Registered! State: {node.state.name}")

    reg = storage.read_registration()
    print(f"Node number: {reg.node_number}, group: {reg.connectivity_group_id}")

    node.close()
    storage.close()
    return 0


def cmd_activate(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)

    if state == NodeState.PENDING:
        print("Cannot activate: not registered yet")
        node.close()
        storage.close()
        return 1
    if state == NodeState.ACTIVATED:
        print("Already activated")
        node.close()
        storage.close()
        return 1

    print(f"Activating with code: {args.code}")
    node.activate(args.code)
    print(f"Activated! State: {node.state.name}")

    node.close()
    storage.close()
    return 0


def cmd_nodes(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)

    if state == NodeState.PENDING:
        print("Not registered yet")
        node.close()
        storage.close()
        return 1

    print_group(node)

    node.close()
    storage.close()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)

    if state == NodeState.PENDING:
        print("Cannot serve: not registered yet")
        node.close()
        storage.close()
        return 1

    reg = storage.read_registration()
    print(f"Node {reg.node_number} in group {reg.connectivity_group_id}")
    print(f"Starting serving session (state: {state.name})...")

    session = node.start_serving()
    serve_in_background(session)
    accept_loop(session)

    # Auto-print activation code if this node can endorse.
    try:
        info = node.group_info()
        if info.state in (GroupState.CAN_ENDORSE, GroupState.BOOTSTRAP):
            code = session.generate_activation_code()
            print(f"\nActivation code for a new peer:\n  {code}\n")
    except Exception:
        pass

    print("Serving (Ctrl-C to quit)...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    session.shutdown()
    session.close()
    node.close()
    storage.close()
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    storage, node, state = init_node(args)

    if state != NodeState.ACTIVATED:
        print(f"Cannot ping: must be ACTIVATED (currently {state.name})")
        node.close()
        storage.close()
        return 1

    peer = args.node_num
    transport = "QUIC" if args.quic else "UDP"
    print(f"Pinging node {peer} via {transport}...")

    start = time.monotonic()

    if args.quic:
        conn = node.connect_quic(peer)
        stream = conn.open_stream()
        stream.write(b"PING\n")
        stream.finish()

        pong_start = time.monotonic()
        reply = stream.read()

        if reply == b"PONG\n":
            print(f"  Pong received in {time.monotonic() - pong_start:.3f}s")
        else:
            print(f"  Unexpected response: {reply!r}")
        stream.close()
        conn.close()
    else:
        conn = node.connect_udp(peer)
        conn.send(b"ping")

        pong_start = time.monotonic()
        reply = conn.recv()

        if reply == b"pong":
            print(f"  Pong received in {time.monotonic() - pong_start:.3f}s")
        else:
            print(f"  Unexpected response: {reply!r}")
        conn.close()

    print(f"Ping successful! Total time: {time.monotonic() - start:.3f}s")

    node.close()
    storage.close()
    return 0


# =============================================================================
# Serve helpers
# =============================================================================


def serve_in_background(session: ServingSession) -> threading.Thread:
    t = threading.Thread(target=session.run, daemon=True)
    t.start()
    return t


def accept_loop(session: ServingSession) -> None:
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

    print("Listening for incoming connections...")
    threading.Thread(target=accept_quic, daemon=True).start()
    threading.Thread(target=accept_udp, daemon=True).start()


def handle_quic_stream(conn, stream) -> None:  # type: ignore[no-untyped-def]
    try:
        data = stream.read()
        line = data.split(b"\n", 1)[0]
        if line == b"PING":
            print("  Received PING, sending PONG")
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
    try:
        while True:
            data = conn.recv()
            if data == b"ping":
                print("  Received ping, sending pong")
                conn.send(b"pong")
            else:
                print(f"  Received {len(data)} bytes")
    except Exception:
        pass


# =============================================================================
# Node init helpers
# =============================================================================


def init_node(args: argparse.Namespace) -> tuple[NodeStorage, Node, NodeState]:
    storage_dir = Path(args.storage) if args.storage else default_storage_dir()
    storage = NodeStorage.with_file_storage(storage_dir)
    if args.hub:
        storage.override_hub_addr(args.hub)
    node, state = storage.restore_or_init()
    return storage, node, state


def default_storage_dir() -> Path:
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "wispers-connect-examples" / "python"
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return Path(xdg) / "wispers-connect-examples" / "python"


# =============================================================================
# Display helpers
# =============================================================================


def print_group(node: Node) -> None:
    info = node.group_info()
    print(f"  Group state: {info.state.name}")
    for n in info.nodes:
        tag = " (self)" if n.is_self else ""
        online = " [online]" if n.is_online else ""
        print(f"  Node {n.node_number}: {n.name or '(unnamed)'} — {n.state.name}{tag}{online}")


# =============================================================================

if __name__ == "__main__":
    main()
