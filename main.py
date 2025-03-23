import asyncio
import struct

# OpenFlow constants
OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
OFPT_PACKET_OUT = 13
OFPT_PORT_STATUS = 12

OFP_VERSION = 0x04  # OpenFlow 1.3
OFPP_CONTROLLER = 0xFFFFFFFD
OFPP_FLOOD = 0xFFFFFFFB
OFPFC_ADD = 0
OFP_NO_BUFFER = 0xFFFFFFFF

mac_table = {}  # MAC -> port


def ofp_header(msg_type, length, xid=0):
    return struct.pack("!BBHI", OFP_VERSION, msg_type, length, xid)


def features_request():
    return ofp_header(OFPT_FEATURES_REQUEST, 8)


def echo_reply(data, xid):
    length = 8 + len(data)
    return ofp_header(OFPT_ECHO_REPLY, length, xid) + data


def packet_out(buffer_id, in_port, actions, data=b""):
    max_len = 0xFFFF
    action_list = b""

    for port in actions:
        action_type = 0  # OFPAT_OUTPUT
        action_len = 16
        action = struct.pack("!HHIH6x", action_type, action_len, port, max_len)
        action_list += action

    total_len = 24 + len(action_list) + len(data)
    header = ofp_header(OFPT_PACKET_OUT, total_len)
    body = (
        struct.pack("!IHH", buffer_id, in_port, len(action_list)) + action_list + data
    )
    return header + body


def flow_mod(dst_mac, out_port):
    match_type = 1  # OFPMT_OXM
    oxm_class = 0x8000
    oxm_field = 6  # ETH_DST
    oxm_length = 6
    oxm_header = struct.pack("!HBB", oxm_class, oxm_field << 1, oxm_length)
    oxm_entries = oxm_header + dst_mac

    match_len = len(oxm_entries) + 4
    padding = b"\x00" * ((8 - match_len % 8) % 8)
    match = struct.pack("!HH", match_type, match_len) + oxm_entries + padding

    instruction_type = 4  # APPLY_ACTIONS
    instruction_len = 24
    action_type = 0  # OUTPUT
    action_len = 16
    max_len = 0xFFFF
    action = struct.pack("!HHIH6x", action_type, action_len, out_port, max_len)
    instruction = struct.pack("!HH4x", instruction_type, instruction_len) + action

    length = 56 + len(match) + len(instruction)
    header = ofp_header(OFPT_FLOW_MOD, length)

    body = (
        struct.pack(
            "!QQBBHHHIIIHH2x", 0, 0, 0, OFPFC_ADD, 0, 0, 1, OFP_NO_BUFFER, 0, 0, 0, 0
        )
        + match
        + instruction
    )

    return header + body


topology = {}  # MAC -> Switch:Port


def print_topology():
    print("\n[\U0001f310] Текущая топология сети:")
    print("Switch_Port".ljust(20), "⇔", "MAC")
    print("-" * 40)
    for mac, (switch, port) in topology.items():
        print(f"{switch}:{port}".ljust(20), "⇔", f"{mac.hex(':')}")
    print("-" * 40, "\n")


async def handle_switch(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[+] Switch connected from {addr}")

    datapath_id = None

    try:
        writer.write(ofp_header(OFPT_HELLO, 8))
        await writer.drain()

        # Ждём ответ HELLO
        header = await reader.readexactly(8)
        version, msg_type, length, xid = struct.unpack("!BBHI", header)
        body = await reader.readexactly(length - 8)

        if msg_type != OFPT_HELLO:
            print(f"[!] Unexpected message type {msg_type}, expected HELLO")
            return

        print("[*] Received HELLO from switch.")

        writer.write(features_request())
        await writer.drain()

        while True:
            header = await reader.readexactly(8)
            version, msg_type, length, xid = struct.unpack("!BBHI", header)
            body = await reader.readexactly(length - 8)

            if msg_type == OFPT_ERROR:
                err_type, err_code = struct.unpack("!HH", body[:4])
                print(
                    f"[!] Error message from switch: type={err_type}, code={err_code}"
                )

            elif msg_type == OFPT_ECHO_REQUEST:
                print("[*] ECHO_REQUEST received, sending ECHO_REPLY.")
                writer.write(echo_reply(body, xid))
                try:
                    await writer.drain()
                except ConnectionResetError:
                    print(f"[!] Connection reset during echo reply to {addr}")
                    break

            elif msg_type == OFPT_FEATURES_REPLY:

                print(f"[+] OFPT_FEATURES_REPLY was recived!")

                datapath_id = struct.unpack("!Q", body[:8])[0]
                print(
                    f"[+] Switch features reply received, Datapath ID: {datapath_id:#x}"
                )

            elif msg_type == OFPT_PORT_STATUS:
                reason, pad = struct.unpack("!B7s", body[:8])
                (port_no,) = struct.unpack("!I", body[8:12])
                reasons = {0: "ADD", 1: "DELETE", 2: "MODIFY"}
                reason_str = reasons.get(reason, f"UNKNOWN({reason})")
                print(
                    f"[\u26a1] Port status change detected: Port={port_no}, Reason={reason_str}"
                )

            elif msg_type == OFPT_PACKET_IN:
                buffer_id = struct.unpack("!I", body[:4])[0]
                in_port = struct.unpack("!I", body[8:12])[0]
                eth_frame = body[26:]

                if len(eth_frame) < 14:
                    continue

                dst_mac = eth_frame[0:6]
                src_mac = eth_frame[6:12]

                mac_table[src_mac] = in_port
                topology[src_mac] = (f"Switch_{datapath_id:#x}", in_port)

                out_port = mac_table.get(dst_mac, OFPP_FLOOD)

                if out_port != OFPP_FLOOD:
                    writer.write(flow_mod(dst_mac, out_port))

                pkt_out = packet_out(OFP_NO_BUFFER, in_port, [out_port], eth_frame)
                writer.write(pkt_out)

                try:
                    await writer.drain()
                except ConnectionResetError:
                    print(f"[!] Connection reset by {addr} during write.")
                    break

                print_topology()

            else:
                print(f"[?] Unknown message type received: {msg_type}")

    except asyncio.IncompleteReadError:
        print(f"[-] Switch {addr} disconnected")
    except ConnectionResetError:
        print(f"[-] Switch {addr} connection reset")
    except Exception as e:
        print(f"[!] Error handling switch {addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    server = await asyncio.start_server(handle_switch, "0.0.0.0", 6653)
    print("[*] Listening on port 6653")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
