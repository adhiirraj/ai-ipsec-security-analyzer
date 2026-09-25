#!/usr/bin/env python3
"""Recursive directory-to-PCAP simulator with pluggable file encryption.

Educational custom X25519 exchange and authenticated ESP-style packets.
Not interoperable with real IKEv2 or ESP. The exchange is NOT authenticated.
"""
import argparse
import hashlib
import hmac
import json
import os
import struct
import time
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scapy.all import Ether, IP, UDP, Raw, PcapReader, PcapWriter

import crypto_backend as backend

SRC, DST = '192.0.2.10', '198.51.100.20'
SMAC, DMAC = '02:00:00:00:00:01', '02:00:00:00:00:02'
MAGIC, VERSION = b'ISIM', 3
IKE_FMT = '!4sBBI16s32s'   # custom exchange, not actual IKEv2
ESP_FMT = '!II'            # SPI, sequence
FRAG_FMT = '!16sII'        # file ID, fragment index, fragment count
TAG_LEN, CHUNK = 16, 1100
MAX_META = 65536


def pub(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive(private, peer_public, salt, spi):
    secret = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'ISIM-v3-master' + struct.pack('!I', spi)).derive(secret)


def file_keys(master, file_id):
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=file_id,
                    info=b'ISIM-v3-file').derive(master)
    return material[:32], material[32:]


def safe_relative_path(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe relative path in PCAP')
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('Unsafe relative path in PCAP')
    if ':' in name.split('/')[0]:
        raise ValueError('Unsafe relative path in PCAP')
    return Path(*path.parts)


def inputs_from_paths(inputs):
    """Return (source path, portable relative path) pairs."""
    found = {}
    for raw in inputs:
        source = Path(raw).expanduser().resolve()
        if source.is_file():
            candidates = [(source, Path(source.name))]
        elif source.is_dir():
            candidates = [(p, Path(source.name) / p.relative_to(source))
                          for p in sorted(source.rglob('*')) if p.is_file() and not p.is_symlink()]
        else:
            raise ValueError(f'Input not found or unsupported: {raw}')
        for path, rel in candidates:
            name = rel.as_posix()
            safe_relative_path(name)
            if name in found:
                raise ValueError(f'Duplicate output path: {name}; supply distinct input roots')
            found[name] = path
    if not found:
        raise ValueError('No regular files found')
    return [(path, name) for name, path in sorted(found.items())]


def write_new(path, data, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def ike_packet(kind, spi, salt, public):
    reverse = kind == 2
    return (Ether(src=DMAC if reverse else SMAC, dst=SMAC if reverse else DMAC)
            / IP(src=DST if reverse else SRC, dst=SRC if reverse else DST)
            / UDP(sport=500, dport=500)
            / Raw(struct.pack(IKE_FMT, MAGIC, VERSION, kind, spi, salt, public)))


def generate(args):
    inputs = inputs_from_paths(args.inputs)
    out = Path(args.out).expanduser().resolve()
    # Avoid recursively including existing outputs in the input tree.
    for raw in args.inputs:
        root = Path(raw).expanduser().resolve()
        if root.is_dir() and (out == root or root in out.parents):
            raise ValueError('Output directory must be outside input directories')
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f'Output directory must be empty: {out}')
    out.mkdir(parents=True, exist_ok=True)
    sender = x25519.X25519PrivateKey.generate()
    receiver = x25519.X25519PrivateKey.generate()
    salt, spi = os.urandom(16), int.from_bytes(os.urandom(4), 'big')
    master = derive(sender, pub(receiver), salt, spi)
    if master != derive(receiver, pub(sender), salt, spi):
        raise RuntimeError('Key agreement failed')
    pem = receiver.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    write_new(out / 'receiver_private.pem', pem, private=True)
    sequence, count = 0, 0
    now = time.time()
    with PcapWriter(str(out / 'traffic.pcap'), linktype=1, sync=True) as writer:
        for kind, public in [(1, pub(sender)), (2, pub(receiver))]:
            pkt = ike_packet(kind, spi, salt, public)
            pkt.time = now + count * .001
            writer.write(pkt)
            count += 1
        for path, name in inputs:
            plain = path.read_bytes()
            file_id = os.urandom(16)
            encryption_key, mac_key = file_keys(master, file_id)
            ciphertext, params = backend.encrypt(plain, encryption_key)
            meta = {'path': name, 'algorithm': backend.ALGORITHM,
                    'parameters': params, 'size': len(plain),
                    'sha256': hashlib.sha256(plain).hexdigest()}
            encoded_meta = json.dumps(meta, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            if len(encoded_meta) > MAX_META:
                raise ValueError(f'Metadata too large for {name}')
            blob = struct.pack('!I', len(encoded_meta)) + encoded_meta + ciphertext
            total = max(1, (len(blob) + CHUNK - 1) // CHUNK)
            if sequence + total > 0xffffffff:
                raise ValueError('ESP sequence counter exhausted')
            for index in range(total):
                sequence += 1
                chunk = blob[index * CHUNK:(index + 1) * CHUNK]
                body = (struct.pack(ESP_FMT, spi, sequence)
                        + struct.pack(FRAG_FMT, file_id, index, total) + chunk)
                tag = hmac.new(mac_key, body, hashlib.sha256).digest()[:TAG_LEN]
                pkt = (Ether(src=SMAC, dst=DMAC)
                       / IP(src=SRC, dst=DST, proto=50, id=sequence % 65536)
                       / Raw(body + tag))
                pkt.time = now + count * .001
                writer.write(pkt)
                count += 1
            write_new(out / 'encrypted' / (name + '.enc'), ciphertext)
            print(f'{name}: {len(plain)} bytes -> {total} ESP-style packets')
    print(f'Created {out / "traffic.pcap"} ({count} packets, {len(inputs)} files)')
    print(f'Receiver key: {out / "receiver_private.pem"}')


def read_capture(pcap):
    init = response = None
    streams = {}
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            if UDP in pkt and pkt[UDP].sport == pkt[UDP].dport == 500:
                raw = bytes(pkt[UDP].payload)
                if len(raw) != struct.calcsize(IKE_FMT):
                    continue
                magic, version, kind, spi, salt, public = struct.unpack(IKE_FMT, raw)
                if (magic, version) != (MAGIC, VERSION):
                    continue
                if kind == 1 and pkt[IP].src == SRC and pkt[IP].dst == DST:
                    if init is not None:
                        raise ValueError('Duplicate key-exchange INIT')
                    init = (spi, salt, public)
                elif kind == 2 and pkt[IP].src == DST and pkt[IP].dst == SRC:
                    if response is not None:
                        raise ValueError('Duplicate key-exchange RESPONSE')
                    response = (spi, salt, public)
            elif pkt[IP].proto == 50 and pkt[IP].src == SRC and pkt[IP].dst == DST:
                raw = bytes(pkt[IP].payload)
                if len(raw) < struct.calcsize(ESP_FMT) + struct.calcsize(FRAG_FMT) + TAG_LEN:
                    continue
                spi, seq = struct.unpack_from(ESP_FMT, raw)
                fid, index, total = struct.unpack_from(FRAG_FMT, raw, struct.calcsize(ESP_FMT))
                streams.setdefault((spi, fid), []).append((seq, index, total, raw))
    if init is None or response is None or init[:2] != response[:2]:
        raise ValueError('Incomplete or inconsistent key exchange')
    return init, response, streams


def recover(args):
    init, response, streams = read_capture(args.pcap)
    spi, salt, sender_public = init
    receiver = serialization.load_pem_private_key(
        Path(args.receiver_key).read_bytes(), password=None)
    if not isinstance(receiver, x25519.X25519PrivateKey) or pub(receiver) != response[2]:
        raise ValueError('Receiver private key does not match PCAP')
    master = derive(receiver, sender_public, salt, spi)
    out = Path(args.out).expanduser().resolve()
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f'Recovery directory must be empty: {out}')
    matches = [(fid, rows) for (s, fid), rows in streams.items() if s == spi]
    if not matches:
        raise ValueError('No ESP packets matching negotiated SPI')
    # Verify all transfers before writing recovered files.
    recovered = []
    seen = set()
    for fid, rows in matches:
        encryption_key, mac_key = file_keys(master, fid)
        parts, expected_total, seq_seen = {}, None, set()
        for seq, index, total, raw in rows:
            if not seq or total < 1 or index >= total:
                raise ValueError('Invalid sequence or fragment metadata')
            if expected_total is None:
                expected_total = total
            if total != expected_total:
                raise ValueError('Conflicting fragment count')
            expected_tag = hmac.new(mac_key, raw[:-TAG_LEN], hashlib.sha256).digest()[:TAG_LEN]
            if not hmac.compare_digest(expected_tag, raw[-TAG_LEN:]):
                raise ValueError(f'Authentication failed at ESP sequence {seq}')
            if seq in seq_seen:
                raise ValueError(f'Duplicate ESP sequence {seq}')
            seq_seen.add(seq)
            chunk = raw[struct.calcsize(ESP_FMT) + struct.calcsize(FRAG_FMT):-TAG_LEN]
            if index in parts:
                raise ValueError('Duplicate fragment index')
            parts[index] = chunk
        if len(parts) != expected_total:
            raise ValueError(f'Missing {expected_total - len(parts)} fragments for {fid.hex()}')
        blob = b''.join(parts[i] for i in range(expected_total))
        if len(blob) < 4:
            raise ValueError('Missing metadata length')
        meta_len = struct.unpack_from('!I', blob)[0]
        if meta_len > MAX_META or len(blob) < 4 + meta_len:
            raise ValueError('Invalid metadata length')
        meta = json.loads(blob[4:4 + meta_len])
        name = meta['path']
        relative = safe_relative_path(name)
        if name in seen:
            raise ValueError(f'Duplicate path in capture: {name}')
        seen.add(name)
        if meta['algorithm'] != backend.ALGORITHM:
            raise ValueError(f'Unsupported encryption algorithm: {meta["algorithm"]}')
        ciphertext = blob[4 + meta_len:]
        plain = backend.decrypt(ciphertext, encryption_key, meta['parameters'])
        if len(plain) != meta['size'] or hashlib.sha256(plain).hexdigest() != meta['sha256']:
            raise ValueError(f'Plaintext verification failed: {name}')
        recovered.append((relative, ciphertext, plain, len(parts)))
    out.mkdir(parents=True, exist_ok=True)
    for relative, ciphertext, plain, packet_count in recovered:
        if args.mode in ('extract', 'both'):
            write_new(out / 'encrypted' / (str(relative) + '.enc'), ciphertext)
        if args.mode in ('decrypt', 'both'):
            write_new(out / 'decrypted' / relative, plain)
        print(f'Recovered {relative.as_posix()}: {packet_count} authenticated packets')
    print(f'Recovered {len(recovered)} files into {out}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encrypt', help='Recursively encrypt files/directories into one PCAP')
    enc.add_argument('inputs', nargs='+', help='Files and/or directories')
    enc.add_argument('--out', default='encrypted_output')
    rec = commands.add_parser('recover', help='Extract and/or decrypt all files from PCAP')
    rec.add_argument('pcap')
    rec.add_argument('--receiver-key', required=True)
    rec.add_argument('--out', default='recovered_output')
    rec.add_argument('--mode', choices=('extract', 'decrypt', 'both'), default='both')
    args = parser.parse_args()
    if args.command == 'encrypt':
        generate(args)
    else:
        recover(args)


if __name__ == '__main__':
    main()
