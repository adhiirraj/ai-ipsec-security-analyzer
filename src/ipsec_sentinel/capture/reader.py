"""Streaming readers for classic libpcap and common PCAPNG captures.

The implementation intentionally avoids loading a whole capture into memory.
It does not invoke external dissectors and treats malformed lengths as errors
rather than attempting to recover from possibly ambiguous packet boundaries.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ipsec_sentinel.capture.models import CaptureFileInfo, RawPacket
from ipsec_sentinel.config.settings import DEFAULT_MAX_CAPTURED_PACKET_BYTES


class PcapError(ValueError):
    """The supplied file is not a safe, parseable PCAP/PCAPNG capture."""


_CLASSIC_MAGICS: dict[bytes, tuple[str, float]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_PCAPNG_SECTION_HEADER = 0x0A0D0D0A
_PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
_PCAPNG_PACKET_BLOCK = 0x00000002
_PCAPNG_SIMPLE_PACKET_BLOCK = 0x00000003
_PCAPNG_ENHANCED_PACKET_BLOCK = 0x00000006


def _read_exact(handle: BinaryIO, size: int, context: str) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        raise PcapError(f"truncated {context}")
    return value


def _padded_length(length: int) -> int:
    return (length + 3) & ~3


@dataclass(slots=True)
class _PcapNgInterface:
    link_type: int
    timestamp_resolution: float = 1e-6


class PcapReader:
    """Open and stream one capture file.

    The reader currently supports classic libpcap plus PCAPNG section,
    interface-description, enhanced-packet, packet, and simple-packet blocks.
    Unrecognised PCAPNG blocks are skipped after their length is validated.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_captured_packet_bytes: int = DEFAULT_MAX_CAPTURED_PACKET_BYTES,
    ) -> None:
        self.path = Path(path)
        if max_captured_packet_bytes <= 0:
            raise ValueError("max_captured_packet_bytes must be positive")
        self.max_captured_packet_bytes = max_captured_packet_bytes
        self._info: CaptureFileInfo | None = None

    @property
    def info(self) -> CaptureFileInfo | None:
        """Container information once iteration has begun."""

        return self._info

    def __iter__(self) -> Iterator[RawPacket]:
        if not self.path.is_file():
            raise PcapError(f"capture file does not exist or is not a file: {self.path}")

        with self.path.open("rb") as handle:
            first_four = _read_exact(handle, 4, "capture header")
            if first_four in _CLASSIC_MAGICS:
                yield from self._iter_classic(handle, first_four)
            elif first_four == struct.pack("<I", _PCAPNG_SECTION_HEADER):
                yield from self._iter_pcapng(handle, first_four)
            else:
                raise PcapError("unsupported capture format; expected libpcap or PCAPNG")

    def _iter_classic(self, handle: BinaryIO, magic: bytes) -> Iterator[RawPacket]:
        endian, resolution = _CLASSIC_MAGICS[magic]
        header = _read_exact(handle, 20, "libpcap global header")
        major, minor, _timezone, _sigfigs, snaplen, link_type = struct.unpack(
            f"{endian}HHiIII", header
        )
        if major != 2 or minor != 4:
            raise PcapError(f"unsupported libpcap version {major}.{minor}")
        if snaplen == 0:
            raise PcapError("libpcap snaplen cannot be zero")
        self._info = CaptureFileInfo(
            capture_format="pcap",
            link_types=(link_type,),
            timestamp_resolution="nanoseconds" if resolution == 1e-9 else "microseconds",
        )

        frame_number = 0
        while True:
            record_header = handle.read(16)
            if not record_header:
                return
            if len(record_header) != 16:
                raise PcapError("truncated libpcap packet header")
            seconds, fraction, captured_length, original_length = struct.unpack(
                f"{endian}IIII", record_header
            )
            self._validate_packet_length(captured_length, "libpcap packet")
            packet_data = _read_exact(handle, captured_length, "libpcap packet data")
            frame_number += 1
            yield RawPacket(
                frame_number=frame_number,
                timestamp=seconds + fraction * resolution,
                captured_length=captured_length,
                original_length=original_length,
                link_type=link_type,
                data=packet_data,
            )

    def _iter_pcapng(self, handle: BinaryIO, block_type_raw: bytes) -> Iterator[RawPacket]:
        """Iterate PCAPNG, where a section defines byte order and interfaces."""

        interfaces: list[_PcapNgInterface] = []
        frame_number = 0
        endian: str | None = None
        first_block = True

        while True:
            if first_block:
                block_type = _PCAPNG_SECTION_HEADER
                first_block = False
            else:
                block_type_raw = handle.read(4)
                if not block_type_raw:
                    return
                if len(block_type_raw) != 4:
                    raise PcapError("truncated PCAPNG block type")
                if endian is None:
                    raise PcapError("PCAPNG contains a block before its section header")
                block_type = struct.unpack(f"{endian}I", block_type_raw)[0]

            length_raw = _read_exact(handle, 4, "PCAPNG block length")
            if block_type == _PCAPNG_SECTION_HEADER:
                # The byte-order magic is eight bytes after the block type.
                bom = _read_exact(handle, 4, "PCAPNG byte-order magic")
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise PcapError("invalid PCAPNG byte-order magic")
                block_length = struct.unpack(f"{endian}I", length_raw)[0]
                if block_length < 28 or block_length % 4:
                    raise PcapError("invalid PCAPNG section-header length")
                remaining = _read_exact(handle, block_length - 12, "PCAPNG section header")
                trailer_length = struct.unpack(f"{endian}I", remaining[-4:])[0]
                if trailer_length != block_length:
                    raise PcapError("PCAPNG section-header length trailer does not match")
                interfaces = []
                self._info = CaptureFileInfo(
                    capture_format="pcapng", link_types=(), timestamp_resolution="per-interface"
                )
                continue

            if endian is None:
                raise PcapError("PCAPNG byte order could not be determined")
            block_length = struct.unpack(f"{endian}I", length_raw)[0]
            if block_length < 12 or block_length % 4:
                raise PcapError(f"invalid PCAPNG block length {block_length}")
            content_and_trailer = _read_exact(
                handle, block_length - 8, "PCAPNG block content"
            )
            if struct.unpack(f"{endian}I", content_and_trailer[-4:])[0] != block_length:
                raise PcapError("PCAPNG block length trailer does not match")
            body = content_and_trailer[:-4]

            if block_type == _PCAPNG_INTERFACE_DESCRIPTION:
                interface = self._parse_interface_description(body, endian)
                interfaces.append(interface)
                self._info = CaptureFileInfo(
                    capture_format="pcapng",
                    link_types=tuple(interface_item.link_type for interface_item in interfaces),
                    timestamp_resolution="per-interface",
                )
                continue

            packet: RawPacket | None
            if block_type == _PCAPNG_ENHANCED_PACKET_BLOCK:
                packet = self._parse_enhanced_packet(
                    body, endian, interfaces, frame_number + 1
                )
            elif block_type == _PCAPNG_PACKET_BLOCK:
                packet = self._parse_packet_block(body, endian, interfaces, frame_number + 1)
            elif block_type == _PCAPNG_SIMPLE_PACKET_BLOCK:
                packet = self._parse_simple_packet(body, endian, interfaces, frame_number + 1)
            else:
                packet = None
            if packet is not None:
                frame_number += 1
                yield packet

    def _parse_interface_description(self, body: bytes, endian: str) -> _PcapNgInterface:
        if len(body) < 8:
            raise PcapError("truncated PCAPNG interface-description block")
        link_type, _reserved, _snaplen = struct.unpack(f"{endian}HHI", body[:8])
        resolution = 1e-6
        option_offset = 8
        while option_offset + 4 <= len(body):
            option_code, option_length = struct.unpack(
                f"{endian}HH", body[option_offset : option_offset + 4]
            )
            option_offset += 4
            padded_length = _padded_length(option_length)
            if option_offset + padded_length > len(body):
                raise PcapError("truncated PCAPNG interface option")
            value = body[option_offset : option_offset + option_length]
            option_offset += padded_length
            if option_code == 0:
                break
            if option_code == 9 and len(value) == 1:  # if_tsresol
                raw_resolution = value[0]
                resolution = (
                    2.0 ** -(raw_resolution & 0x7F)
                    if raw_resolution & 0x80
                    else 10.0 ** -raw_resolution
                )
        return _PcapNgInterface(link_type=link_type, timestamp_resolution=resolution)

    def _parse_enhanced_packet(
        self,
        body: bytes,
        endian: str,
        interfaces: list[_PcapNgInterface],
        frame_number: int,
    ) -> RawPacket:
        if len(body) < 20:
            raise PcapError("truncated PCAPNG enhanced-packet block")
        interface_id, timestamp_high, timestamp_low, captured_length, original_length = struct.unpack(
            f"{endian}IIIII", body[:20]
        )
        interface = self._interface_at(interfaces, interface_id)
        self._validate_packet_length(captured_length, "PCAPNG enhanced packet")
        data_end = 20 + captured_length
        if data_end > len(body):
            raise PcapError("truncated PCAPNG enhanced-packet data")
        timestamp_units = (timestamp_high << 32) | timestamp_low
        return RawPacket(
            frame_number=frame_number,
            timestamp=timestamp_units * interface.timestamp_resolution,
            captured_length=captured_length,
            original_length=original_length,
            link_type=interface.link_type,
            data=body[20:data_end],
        )

    def _parse_packet_block(
        self,
        body: bytes,
        endian: str,
        interfaces: list[_PcapNgInterface],
        frame_number: int,
    ) -> RawPacket:
        if len(body) < 20:
            raise PcapError("truncated PCAPNG packet block")
        interface_id, _drops = struct.unpack(f"{endian}HH", body[:4])
        timestamp_high, timestamp_low, captured_length, original_length = struct.unpack(
            f"{endian}IIII", body[4:20]
        )
        interface = self._interface_at(interfaces, interface_id)
        self._validate_packet_length(captured_length, "PCAPNG packet")
        data_end = 20 + captured_length
        if data_end > len(body):
            raise PcapError("truncated PCAPNG packet data")
        return RawPacket(
            frame_number=frame_number,
            timestamp=((timestamp_high << 32) | timestamp_low) * interface.timestamp_resolution,
            captured_length=captured_length,
            original_length=original_length,
            link_type=interface.link_type,
            data=body[20:data_end],
        )

    def _parse_simple_packet(
        self, body: bytes, endian: str, interfaces: list[_PcapNgInterface], frame_number: int
    ) -> RawPacket:
        if len(body) < 4:
            raise PcapError("truncated PCAPNG simple-packet block")
        interface = self._interface_at(interfaces, 0)
        original_length = struct.unpack(f"{endian}I", body[:4])[0]
        captured_length = min(original_length, len(body) - 4)
        self._validate_packet_length(captured_length, "PCAPNG simple packet")
        return RawPacket(
            frame_number=frame_number,
            timestamp=None,
            captured_length=captured_length,
            original_length=original_length,
            link_type=interface.link_type,
            data=body[4 : 4 + captured_length],
        )

    def _interface_at(
        self, interfaces: list[_PcapNgInterface], interface_id: int
    ) -> _PcapNgInterface:
        try:
            return interfaces[interface_id]
        except IndexError as error:
            raise PcapError(f"PCAPNG packet references unknown interface {interface_id}") from error

    def _validate_packet_length(self, captured_length: int, context: str) -> None:
        if captured_length > self.max_captured_packet_bytes:
            raise PcapError(
                f"{context} captured length {captured_length} exceeds configured limit "
                f"{self.max_captured_packet_bytes}"
            )
