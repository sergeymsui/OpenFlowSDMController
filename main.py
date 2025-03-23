import asyncio
import struct

# OpenFlow constants
OFPT_HELLO = 0
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
OFPT_PACKET_OUT = 13

OFP_VERSION = 0x04  # OpenFlow 1.3
OFPP_CONTROLLER = 0xFFFFFFFD
OFPP_FLOOD = 0xFFFFFFFB
OFPFC_ADD = 0
OFP_NO_BUFFER = 0xFFFFFFFF

mac_table = {}  # MAC -> port


def ofp_header(msg_type, length):
    return struct.pack("!BBHI", OFP_VERSION, msg_type, length, 0)


def features_request():
    return ofp_header(OFPT_FEATURES_REQUEST, 8)


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
    oxm_class = 0x8000  # OpenFlow Basic

    oxm_entries = b""

    # Match on eth_dst
    oxm_field = 6  # ETH_DST
    oxm_length = 6
    oxm_header = struct.pack("!HBB", oxm_class, oxm_field << 1, oxm_length)
    oxm_entries += oxm_header + dst_mac

    match_len = len(oxm_entries) + 4
    padding = b"\x00" * ((8 - match_len % 8) % 8)
    match = struct.pack("!HH", match_type, match_len) + oxm_entries + padding

    instructions = b""
    instruction_type = 4  # APPLY_ACTIONS
    instruction_len = 24
    action_type = 0  # OUTPUT
    action_len = 16
    max_len = 0xFFFF

    action = struct.pack("!HHIH6x", action_type, action_len, out_port, max_len)
    instruction = struct.pack("!HH4x", instruction_type, instruction_len) + action
    instructions += instruction

    length = 56 + len(match) + len(instructions)
    header = ofp_header(OFPT_FLOW_MOD, length)

    body = (
        struct.pack(
            "!QQBBHHHIIIHH2x",
            0,
            0,  # cookie, mask
            0,
            OFPFC_ADD,
            0,
            0,  # idle_timeout, hard_timeout
            1,  # priority
            OFP_NO_BUFFER,
            0,
            0,  # out_port, out_group
            0,  # flags
            0,
        )
        + match
        + instructions
    )

    return header + body


async def handle_switch(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[+] Switch connected from {addr}")

    try:
        data = await reader.readexactly(8)
        version, msg_type, length, xid = struct.unpack("!BBHI", data)

        if msg_type == OFPT_HELLO:
            writer.write(ofp_header(OFPT_HELLO, 8))
            writer.write(features_request())
            await writer.drain()

        while True:
            header = await reader.readexactly(8)
            version, msg_type, length, xid = struct.unpack("!BBHI", header)
            body = await reader.readexactly(length - 8)

            print(f"msg_type = {msg_type}")

            if msg_type == OFPT_PACKET_IN:
                (buffer_id,) = struct.unpack("!I", body[:4])
                (in_port,) = struct.unpack("!I", body[8:12])
                eth_frame = body[26:]

                if len(eth_frame) < 14:
                    continue

                dst_mac = eth_frame[0:6]
                src_mac = eth_frame[6:12]

                mac_table[src_mac] = in_port
                out_port = mac_table.get(dst_mac, OFPP_FLOOD)

                if out_port != OFPP_FLOOD:
                    writer.write(flow_mod(dst_mac, out_port))

                if buffer_id == OFP_NO_BUFFER:
                    pkt_out = packet_out(buffer_id, in_port, [out_port], eth_frame)
                else:
                    pkt_out = packet_out(buffer_id, in_port, [out_port])

                writer.write(pkt_out)
                await writer.drain()

                await print(mac_table)

    except asyncio.IncompleteReadError:
        print(f"[-] Switch {addr} disconnected")
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
