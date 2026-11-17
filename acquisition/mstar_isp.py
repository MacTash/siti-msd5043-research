#!/usr/bin/env python3
"""MStar ISP read-only tool for SITI CCH-8000DEI (MSD5043/Kronus).

Talks to the ESP32 ISP reader firmware (separate project, not the UART
bridge). Everything here is read-only: the firmware implements no flash
write/erase path at all.

Usage:
  mstar_isp.py [--port /dev/ttyUSB0] [--baud 921600] scan
  mstar_isp.py [--port /dev/ttyUSB0] info
  mstar_isp.py [--port /dev/ttyUSB0] id
  mstar_isp.py [--port /dev/ttyUSB0] read --offset 0xFE0000 --length 0x10000 --output env1.bin
  mstar_isp.py [--port /dev/ttyUSB0] read --offset 0x000000 --length 0x1000000 --output siti-full.bin
  mstar_isp.py [--port /dev/ttyUSB0] env
  mstar_isp.py [--port /dev/ttyUSB0] serdb-version
"""
import argparse
import os
import sys
import struct
import zlib
import hashlib
import binascii
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

FLASH_BYTES = 0x1000000
ISP_ADDR = 0x49
SERDB_KRONUS = 0x5A
BLOCK = 128


class IspError(Exception):
    pass


class MstarIsp:
    def __init__(self, port, baud=921600, timeout=3.0):
        self.ser = None
        self.port, self.baud, self.timeout = port, baud, timeout
        self.open()

    def open(self):
        self.ser = serial.Serial(self.port, self.baud, timeout=self.timeout, exclusive=True)
        self.ser.setRTS(False)
        self.ser.setDTR(False)
        time.sleep(0.1)
        self._wait_ready()

    def close(self):
        if self.ser:
            self.ser.close()
            self.ser = None

    def _line(self, deadline=None):
        deadline = deadline or (time.time() + self.timeout)
        buf = bytearray()
        while time.time() < deadline:
            ch = self.ser.read(1)
            if not ch:
                return None
            if ch == b"\n":
                return bytes(buf).decode("ascii", "replace").rstrip("\r")
            buf += ch
            if len(buf) > 4096:
                raise IspError(
                    "overlong line (no newline in 4096 B; first 64 B: "
                    + bytes(buf[:64]).hex(" ", 1)
                    + ") — the device is likely not the reader firmware, or the baud rate is wrong"
                )
        return None

    def _expect(self, prefix, deadline=None):
        line = self._line(deadline)
        while line and line.startswith("D "):
            print(line[2:], file=sys.stderr)
            line = self._line(deadline)
        if line is None:
            raise IspError(f"expected {prefix!r}: timeout")
        if not line.startswith(prefix):
            raise IspError(f"expected {prefix!r}, got {line!r}")
        return line

    def _wait_ready(self):
        deadline = time.time() + 5
        while time.time() < deadline:
            line = self._line(deadline)
            if line is None:
                break
            if line.startswith("READY "):
                return True
            if line.startswith("D "):
                print(line[2:], file=sys.stderr)
        print("warn: no READY banner (device may already be running its loop)", file=sys.stderr)
        return False

    def _cmd(self, text):
        self.ser.write((text + "\n").encode("ascii"))

    def ping(self):
        self._cmd("PING")
        return self._expect("PONG", time.time() + self.timeout) == "PONG"

    def info(self):
        self._cmd("INFO")
        return self._expect("INFO", time.time() + self.timeout)

    def scan(self):
        self._cmd("SCAN")
        found = []
        while True:
            line = self._line(time.time() + 30)
            if line is None:
                raise IspError("SCAN: timeout")
            if line.startswith("FOUND 0x"):
                found.append(int(line.split()[1], 16))
            elif line == "DONE":
                return found
            elif line.startswith("ERR "):
                raise IspError(line)

    def _exit_quietly(self):
        """Send EXIT (ends the ISP session); best-effort, never raises."""
        try:
            self._cmd("EXIT")
            self._expect("BYE", time.time() + self.timeout)
        except Exception as e:
            print(f"warning: ISP EXIT failed: {e}", file=sys.stderr)

    def serdb_trace(self):
        self._cmd("SERDBTRACE")
        deadline = time.time() + self.timeout * 3
        while True:
            line = self._line(deadline)
            if line is None:
                raise IspError("SERDBTRACE: timeout")
            if line.startswith("D "):
                print(line[2:], file=sys.stderr)
                continue
            if line.startswith("SERDBTRACE OK"):
                return line
            if line.startswith("ERR "):
                raise IspError(line)
            raise IspError(f"SERDBTRACE: unexpected line {line!r}")

    def serdb_version(self):
        self._cmd("SERDBVERSION")
        deadline = time.time() + self.timeout * 3
        while True:
            line = self._line(deadline)
            if line is None:
                raise IspError("SERDBVERSION: timeout")
            if line.startswith("D "):
                print(line[2:], file=sys.stderr)
                continue
            if line.startswith("SERDBVERSION OK"):
                return line
            if line.startswith("ERR "):
                raise IspError(line)
            raise IspError(f"SERDBVERSION: unexpected line {line!r}")

    def serdb_probe(self):
        self._cmd("SERDBPROBE")
        deadline = time.time() + self.timeout * 3
        while True:
            line = self._line(deadline)
            if line is None:
                raise IspError("SERDBPROBE: timeout")
            if line.startswith("D "):
                print(line[2:], file=sys.stderr)
                continue
            if line.startswith("SERDBPROBE OK"):
                return line
            if line.startswith("ERR "):
                raise IspError(line)
            raise IspError(f"SERDBPROBE: unexpected line {line!r}")

    def serdb_sync(self):
        self._cmd("SERDBSYNC")
        line = self._expect("SERDB", time.time() + self.timeout)
        return line

    def serdb_dump(self, ch, progress=True):
        """Bulk read of the firmware's compiled-in allowlist (read-only).

        Yields ('R'|'E', addr_int, name, value_or_None) per entry, then
        returns the final 'SERDBDUMP OK ...' line; raises on ERR/timeout.
        """
        self._cmd(f"SERDBDUMP {ch}")
        deadline = time.time() + self.timeout * 3
        while True:
            line = self._line(deadline)
            if line is None:
                raise IspError(f"SERDBDUMP {ch}: timeout")
            if line.startswith("D "):
                if progress:
                    print(line[2:], file=sys.stderr)
                continue
            if line.startswith("R ") or line.startswith("E "):
                parts = line.split()
                if len(parts) != (4 if line[0] == "R" else 3):
                    raise IspError(f"SERDBDUMP: bad field count: {line!r}")
                try:
                    addr = int(parts[1], 16)
                except ValueError:
                    raise IspError(f"SERDBDUMP: bad address: {line!r}")
                if addr > 0xFFFF:
                    raise IspError(f"SERDBDUMP: addr out of RIU range: {line!r}")
                name = parts[2]
                if len(name) > 96 or not name.replace("_", "").isalnum():
                    raise IspError(f"SERDBDUMP: bad name: {line!r}")
                if line[0] == "R":
                    try:
                        val = int(parts[3], 16)
                    except ValueError:
                        raise IspError(f"SERDBDUMP: bad value: {line!r}")
                    if not 1 <= len(parts[3]) <= 4 or val > 0xFF:
                        raise IspError(f"SERDBDUMP: value out of byte range: {line!r}")
                    yield ("R", addr, name, val)
                else:
                    yield ("E", addr, name, None)
                deadline = time.time() + self.timeout * 3
            elif line.startswith("SERDBDUMP OK "):
                return line
            elif line.startswith("ERR "):
                raise IspError(line)
            else:
                raise IspError(f"SERDBDUMP: unexpected line {line!r}")

    def id(self):
        try:
            self._cmd("ID")
            line = self._expect("JEDEC", time.time() + self.timeout * 4)
            return bytes.fromhex(line.split()[1])
        finally:
            self._exit_quietly()

    def read(self, offset, length, out_path, resume=False, progress=True):
        try:
            return self._read_block(offset, length, out_path, resume, progress)
        finally:
            self._exit_quietly()

    def _read_block(self, offset, length, out_path, resume=False, progress=True):
        if not (0 <= offset and 0 < length and offset + length <= FLASH_BYTES):
            raise IspError(f"range: offset 0x{offset:x} length 0x{length:x} exceeds 16 MiB flash")
        start = 0
        if resume and os.path.exists(out_path):
            have = os.path.getsize(out_path)
            if have > length:
                raise IspError(f"resume: existing file ({have} B) larger than requested read")
            start = have - (have % BLOCK)
            if start != have:
                with open(out_path, "r+b") as f:
                    f.truncate(start)
            offset += start
            length -= start
            print(f"resume: keeping {start} B, reading {length} B more", file=sys.stderr)

        self._cmd(f"READ {offset:08X} {length:08X}")
        line = self._expect("DATA", time.time() + self.timeout * 4)
        try:
            announced = int(line.split()[1], 16)
        except (IndexError, ValueError):
            raise IspError(f"bad DATA header: {line!r}")
        if announced != length:
            raise IspError(f"DATA header length {announced} != requested {length}")

        got = 0
        crc = 0
        mode = "ab" if resume and start else "wb"
        with open(out_path, mode + "") as f:
            while got < length:
                chunk = self.ser.read(min(65536, length - got))
                if not chunk:
                    raise IspError(f"timeout after {got} B of {length}")
                f.write(chunk)
                crc = zlib.crc32(chunk, crc)
                got += len(chunk)
                if progress and (got % (1024 * 1024) < 65536):
                    print(f"  {got}/{length} B ({100 * got // length}%)", file=sys.stderr)

        line = self._expect("SUM32", time.time() + self.timeout)
        want = line.split()[1]
        if f"{crc & 0xFFFFFFFF:08X}" != want.upper():
            raise IspError(f"CRC32 mismatch: computed {crc:08X}, device reported {want}")
        self._expect("END", time.time() + self.timeout)
        return got

    def _read_sector(self, offset):
        path = f"/tmp/mstar_env_{offset:x}.bin"
        self._read_block(offset, 0x10000, path, resume=False, progress=False)
        return path

    def env(self):
        try:
            p1 = self._read_sector(0xFE0000)
            p2 = self._read_sector(0xFF0000)
        finally:
            self._exit_quietly()
        with open(p1, "rb") as f:
            d1 = f.read()
        with open(p2, "rb") as f:
            d2 = f.read()
        print(f"ENV1 {p1}: {len(d1)} B")
        print(f"ENV2 {p2}: {len(d2)} B")
        print("ENV1 == ENV2:", d1 == d2)
        for name, d in (("ENV1", d1), ("ENV2", d2)):
            print(f"--- {name} ---")
            stored_crc = struct.unpack("<I", d[:4])[0]
            print(f"stored crc32 (LE) = 0x{stored_crc:08X}")
            i = d.find(b"\x00\x00", 4)
            candidates = {"data after 4-byte header": d[4:]}
            if i != -1:
                candidates["up to double-NUL"] = d[4:i]
            for cand, data in candidates.items():
                c = zlib.crc32(data)
                ok = c == stored_crc
                print(f"  crc32({cand}) = 0x{c:08X} {'MATCH' if ok else ''}")
            vars_ = d[4:].split(b"\x00")
            for v in vars_:
                if not v:
                    break
                try:
                    print("   ", v.decode("ascii"))
                except UnicodeDecodeError:
                    print("    <non-ascii>", binascii.hexlify(v[:32]).decode())


def main():
    ap = argparse.ArgumentParser(description="MStar ISP read-only tool (SITI CCH-8000DEI)")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--timeout", type=float, default=3.0)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="I2C bus scan 0x03-0x77 (expect 0x49 on Kronus ISP)")
    sub.add_parser("info", help="reader firmware identity")
    sub.add_parser("id", help="read JEDEC ID via ISP (flash must answer 9F)")
    sub.add_parser("sync", help="re-send the ISP sync sequence")
    sub.add_parser("serdb-sync", help="send SERDB sync to 0x5A (activation test only; no other SERDB commands)")
    sub.add_parser("serdb-version", help="SERDB read of REG_CHIP_VERSION (0x00001ECE, read-only)")
    sub.add_parser("serdb-probe", help="SERDB channel-3 register-read probe (read-only)")
    sub.add_parser("serdb-trace", help="SERDB 3-address register trace (read-only)")
    pr = sub.add_parser("serdb-dump", help="SERDB bulk read of the compiled-in allowlist (read-only)")
    pr.add_argument("channel", type=int, choices=[3, 4])

    pr = sub.add_parser("read", help="read SPI NOR flash")
    pr.add_argument("--offset", required=True, type=lambda s: int(s, 0))
    pr.add_argument("--length", required=True, type=lambda s: int(s, 0))
    pr.add_argument("--output", required=True)
    pr.add_argument("--resume", action="store_true")

    sub.add_parser("env", help="read ENV1/ENV2 (0xFE0000/0xFF0000) and decode")

    args = ap.parse_args()
    try:
        dev = MstarIsp(args.port, args.baud, args.timeout)
        if args.cmd == "scan":
            found = dev.scan()
            for a in found:
                tag = {ISP_ADDR: "ISP (SPI NOR bridge)", SERDB_KRONUS: "SERDB (Kronus debug)"}.get(a, "")
                print(f"0x{a:02X} {tag}")
            print("scan complete" if found else "no devices found")
        elif args.cmd == "info":
            print(dev.info())
        elif args.cmd == "id":
            print("JEDEC:", dev.id().hex().upper())
        elif args.cmd == "serdb-version":
            print(dev.serdb_version())
        elif args.cmd == "serdb-trace":
            print(dev.serdb_trace())
        elif args.cmd == "serdb-probe":
            print(dev.serdb_probe())
        elif args.cmd == "serdb-sync":
            print(dev.serdb_sync())
        elif args.cmd == "serdb-dump":
            for status, addr, name, val in dev.serdb_dump(args.channel):
                if status == "R":
                    print(f"R {addr:04X} {name} 0x{val:02X}")
                else:
                    print(f"E {addr:04X} {name}")
        elif args.cmd == "sync":
            dev._cmd("SYNC")
            print(dev._expect("OK", time.time() + dev.timeout))
        elif args.cmd == "read":
            t0 = time.time()
            got = dev.read(args.offset, args.length, args.output, resume=args.resume)
            h = hashlib.sha256()
            with open(args.output, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            print(f"read {got} B -> {args.output} in {time.time()-t0:.1f}s")
            print(f"sha256: {h.hexdigest()}")
        elif args.cmd == "env":
            dev.env()
        dev.close()
    except IspError as e:
        sys.exit(f"error: {e}")
    except serial.SerialException as e:
        sys.exit(f"serial: {e}")


if __name__ == "__main__":
    main()
