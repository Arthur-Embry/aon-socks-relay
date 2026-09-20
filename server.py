#!/usr/bin/env python3
"""SOCKS5 RFC 1928 + RFC 1929 + UDP ASSOCIATE. Runs ON the platform.

Bind 0.0.0.0 here on purpose — this process is the exit, not a laptop facade.
Requires SOCKS_USER and SOCKS_PASS. No anonymous method.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import socket
import struct
import sys

BIND = os.environ.get("BIND", "0.0.0.0")
PORT = int(os.environ.get("SOCKS_PORT") or os.environ.get("PORT") or "1080")
USER = os.environ.get("SOCKS_USER") or ""
PASS = os.environ.get("SOCKS_PASS") or ""


async def _pipe(a: asyncio.StreamReader, b: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await a.read(65536)
            if not chunk:
                break
            b.write(chunk)
            await b.drain()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            b.close()
        except Exception:
            pass


async def _dst(reader: asyncio.StreamReader, atyp: int) -> tuple[str, int]:
    if atyp == 0x01:
        host = ".".join(str(b) for b in await reader.readexactly(4))
    elif atyp == 0x03:
        ln = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(ln)).decode("ascii", "replace")
    elif atyp == 0x04:
        raw = await reader.readexactly(16)
        host = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        raise ValueError("atyp")
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    return host, port


def _parse_udp(data: bytes) -> tuple[str, int, bytes] | None:
    if len(data) < 7 or data[0:2] != b"\x00\x00" or data[2] != 0:
        return None
    atyp = data[3]
    i = 4
    try:
        if atyp == 0x01:
            host = socket.inet_ntoa(data[i:i + 4])
            i += 4
        elif atyp == 0x03:
            ln = data[i]
            i += 1
            host = data[i:i + ln].decode("ascii")
            i += ln
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, data[i:i + 16])
            i += 16
        else:
            return None
        port = struct.unpack(">H", data[i:i + 2])[0]
        return host, port, data[i + 2:]
    except (OSError, struct.error, UnicodeDecodeError, IndexError):
        return None


def _pack_udp(host: str, port: int, payload: bytes) -> bytes:
    try:
        return b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port) + payload
    except OSError:
        pass
    try:
        return b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack(">H", port) + payload
    except OSError:
        pass
    hb = host.encode("idna")[:255]
    return b"\x00\x00\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port) + payload


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, role: str) -> None:
        self.role = role
        self.transport: asyncio.DatagramTransport | None = None
        self.other: _Udp | None = None
        self.client: tuple | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if self.role == "client":
            self.client = addr
            parsed = _parse_udp(data)
            if not parsed or self.other is None or self.other.transport is None:
                return
            host, port, payload = parsed
            try:
                dest = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][:2]
                self.other.transport.sendto(payload, dest)
            except OSError:
                return
            return
        if self.other is None or self.other.transport is None or self.other.client is None:
            return
        self.other.transport.sendto(_pack_udp(addr[0], addr[1], data), self.other.client)


async def _udp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    loop = asyncio.get_running_loop()
    client, wan = _Udp("client"), _Udp("wan")
    client.other, wan.other = wan, client
    ct, _ = await loop.create_datagram_endpoint(lambda: client, local_addr=(BIND, 0))
    wt, _ = await loop.create_datagram_endpoint(lambda: wan, local_addr=(BIND, 0))
    bnd = ct.get_extra_info("sockname")[1]
    writer.write(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", bnd))
    await writer.drain()
    try:
        while True:
            if not await reader.read(65536):
                break
    finally:
        ct.close()
        wt.close()


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if head[0] != 0x05:
            return
        methods = await reader.readexactly(head[1])
        if 0x02 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x02")
        await writer.drain()
        auth = await reader.readexactly(2)
        if auth[0] != 0x01:
            return
        user = (await reader.readexactly(auth[1])).decode("utf-8", "replace")
        pw = (await reader.readexactly((await reader.readexactly(1))[0])).decode("utf-8", "replace")
        if not secrets.compare_digest(user, USER) or not secrets.compare_digest(pw, PASS):
            writer.write(b"\x01\x01")
            await writer.drain()
            return
        writer.write(b"\x01\x00")
        await writer.drain()
        req = await reader.readexactly(4)
        if req[0] != 0x05:
            return
        cmd, atyp = req[1], req[3]
        try:
            host, port = await _dst(reader, atyp)
        except ValueError:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        if cmd == 0x03:
            await _udp(reader, writer)
            return
        if cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        try:
            rr, rw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=20)
        except Exception:
            writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        await asyncio.gather(_pipe(reader, rw), _pipe(rr, writer))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    if not USER or not PASS:
        sys.exit("SOCKS_USER and SOCKS_PASS are required")
    server = await asyncio.start_server(_handle, BIND, PORT)
    socks = server.sockets[0].getsockname() if server.sockets else (BIND, PORT)
    print(f"socks5 rfc1929 {socks[0]}:{socks[1]}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
