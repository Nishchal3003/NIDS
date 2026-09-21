"""Interactive terminal companion for the NIDS-Live room.

Usage:
    python terminal_client.py http://127.0.0.1:5000 your-name

Commands:
    /help                 Show commands
    /name NEW_NAME        Change your display name
    /file PATH            Send a file to the room
    /dos                  Send a bounded SYN test to the configured target
    /scan                 Send a bounded port scan to the configured target
    /stop                 Stop the packet test
    /quit                 Leave the room
"""
import base64
import os
import sys
import threading
import time

import socketio

server = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
name = sys.argv[2] if len(sys.argv) > 2 else "terminal-user"
sio = socketio.Client(reconnection=True, reconnection_attempts=0, logger=False, engineio_logger=False)
print_lock = threading.Lock()


def prompt():
    print("> ", end="", flush=True)


def say(message=""):
    with print_lock:
        print(f"\r{message}")
        prompt()


@sio.event
def connect():
    sio.emit("set_name", {"name": name})
    say(f"[connected] {server} as {name} · type /help for commands")


@sio.event
def disconnect():
    say("[offline] connection lost; retrying automatically…")


@sio.on("chat_message")
def on_chat(data):
    timestamp = time.strftime("%H:%M", time.localtime(data.get("ts", time.time())))
    say(f"[{timestamp}] {data.get('name', 'unknown')}: {data.get('text', '')}")


@sio.on("file_message")
def on_file(data):
    say(f"[file] {data.get('name', 'unknown')} shared {data.get('filename', 'file')}")


@sio.on("system")
def on_system(data):
    say(f"[system] {data.get('msg', '')}")


@sio.on("roster")
def on_roster(data):
    say(f"[room] {len(data.get('clients', []))} online: {', '.join(data.get('clients', []))}")


@sio.on("packet_test_status")
def on_packet_test_status(data):
    if data.get("error"):
        say(f"[error] {data['error']}")
    else:
        say(f"[packet-test] {data.get('status', 'running')} {data.get('kind', '')} {data.get('target', '')}")


def send_file(path):
    if not os.path.isfile(path):
        say(f"[error] file not found: {path}")
        return
    size = os.path.getsize(path)
    if size > 15 * 1024 * 1024:
        say("[error] file is larger than the 15 MB client limit")
        return
    try:
        with open(path, "rb") as handle:
            content = base64.b64encode(handle.read()).decode("ascii")
        sio.emit("file_message", {
            "filename": os.path.basename(path),
            "mime": "application/octet-stream",
            "content": content,
        })
        say(f"[sent] {os.path.basename(path)} ({size:,} bytes)")
    except OSError as exc:
        say(f"[error] could not read file: {exc}")


def handle_command(text):
    global name
    command, _, value = text.partition(" ")
    command = command.lower()
    value = value.strip()
    if command == "/help":
        say("Commands: /help, /name NEW_NAME, /file PATH, /dos, /scan, /stop, /quit")
    elif command == "/name":
        if not value:
            say("[error] usage: /name NEW_NAME")
            return
        name = value[:24]
        sio.emit("set_name", {"name": name})
        say(f"[system] display name changed to {name}")
    elif command == "/file":
        if not value:
            say("[error] usage: /file PATH")
        else:
            send_file(value.strip('"'))
    elif command == "/dos":
        sio.emit("start_packet_test", {"kind": "syn_dos"})
    elif command == "/scan":
        sio.emit("start_packet_test", {
            "kind": "portscan",
            "ports": [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080, 8443],
        })
    elif command == "/stop":
        sio.emit("stop_packet_test")
        say("[packet-test] stop requested")
    elif command == "/quit":
        sio.disconnect()
        raise SystemExit
    else:
        say("[error] unknown command; type /help")


def input_loop():
    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text.startswith("/"):
                handle_command(text)
            else:
                sio.emit("chat_message", {"text": text[:2000]})
    except (EOFError, KeyboardInterrupt):
        if sio.connected:
            sio.sleep(0.2)
            sio.disconnect()


if __name__ == "__main__":
    try:
        sio.connect(server, wait_timeout=10)
        input_loop()
    except socketio.exceptions.ConnectionError as exc:
        print(f"[error] could not connect to {server}: {exc}")
        sys.exit(1)
