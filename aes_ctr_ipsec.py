#!/usr/bin/env python3
"""Educational multi-file AES-CTR + authenticated ESP-style PCAP simulation.
Not interoperable IKEv2/ESP. Preserving a prefix does not guarantee file validity.
"""
import argparse
import hashlib
import hmac
import json
import os
import struct
import time
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scapy.all import Ether, IP, UDP, Raw, wrpcap, PcapReader

SRC, DST = '192.0.2.10', '198.51.100.20'
SMAC, DMAC = '02:00:00:00:00:01', '02:00:00:00:00:02'
MAGIC, VERSION = b'ISIM', 2
IKE_FMT = '!4sBBI16s32s'  # magic, version, type, spi, salt, public key
ESP_FMT = '!II'           # spi, sequence
FRAG_FMT = '!16sII'       # file ID, chunk index, chunk count
TAG_LEN, CHUNK = 16, 1100
# Example policy, NOT a claim that this makes the output a valid image/document.
DEFAULT_PREFIX = {'.jpg': 0, '.jpeg': 0, '.png': 0, '.pdf': 0,
                   '.zip': 0, '.mp4': 0, '.bmp': 0}


def pub(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive(priv, peer, salt, spi):
    secret = priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'ISIM-v2-master' + struct.pack('!I', spi)).derive(secret)


def file_keys(master, file_id):
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=file_id,
                    info=b'ISIM-v2-file').derive(master)
    return material[:32], material[32:]


def crypt(key, nonce, payload):
    ctx = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return ctx.update(payload) + ctx.finalize()


def ike_packet(kind, spi, salt, public):
    reverse = kind == 2
    return (Ether(src=DMAC if reverse else SMAC, dst=SMAC if reverse else DMAC)
            / IP(src=DST if reverse else SRC, dst=SRC if reverse else DST)
            / UDP(sport=500, dport=500)
            / Raw(struct.pack(IKE_FMT, MAGIC, VERSION, kind, spi, salt, public)))


def safe_name(name):
    # Do not accept paths or special names from untrusted PCAP metadata.
    if not isinstance(name, str) or not name or name in ('.', '..'):
        raise ValueError('Invalid filename in metadata')
    if '/' in name or '\\' in name or '\x00' in name or Path(name).name != name:
        raise ValueError('Unsafe filename in metadata')
    return name


def load_manifest(path):
    if path is None:
        return {}
    obj = json.loads(Path(path).read_text())
    if not isinstance(obj, dict):
        raise ValueError('Prefix config must be a JSON object')
    return {str(k).lower(): int(v) for k, v in obj.items()}


def resolve_prefix(path, explicit, config):
    if explicit is not None:
        x = explicit
    else:
        x = config.get(path.suffix.lower(), DEFAULT_PREFIX.get(path.suffix.lower(), 0))
    if x < 0 or x > path.stat().st_size:
        raise ValueError(f'Invalid preserved prefix for {path}: {x}')
    return x


def create_output(path, data, private=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def generate(args):
    files = [Path(p) for p in args.files]
    if not files or any(not p.is_file() for p in files):
        raise ValueError('All inputs must be existing regular files')
    names = [safe_name(p.name) for p in files]
    if len(names) != len(set(names)):
        raise ValueError('Input basenames must be unique')
    out = Path(args.out)
    if out.exists() and not out.is_dir():
        raise ValueError('Output directory is not a directory')
    out.mkdir(parents=True, exist_ok=True)
    if any((out / (n + '.enc')).exists() for n in names):
        raise FileExistsError('An encrypted output already exists')
    if (out / 'traffic.pcap').exists() or (out / 'receiver_private.pem').exists():
        raise FileExistsError('PCAP or private key already exists')
    cfg = load_manifest(args.prefix_config)
    sender, receiver = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    salt, spi = os.urandom(16), int.from_bytes(os.urandom(4), 'big')
    master = derive(sender, pub(receiver), salt, spi)
    assert master == derive(receiver, pub(sender), salt, spi)
    packets = [ike_packet(1, spi, salt, pub(sender)),
               ike_packet(2, spi, salt, pub(receiver))]
    sequence = 0
    for path, name in zip(files, names):
        plain = path.read_bytes()
        x = resolve_prefix(path, args.preserve, cfg)
        file_id, nonce = os.urandom(16), os.urandom(16)
        aes_key, mac_key = file_keys(master, file_id)
        encrypted = plain[:x] + crypt(aes_key, nonce, plain[x:])
        # Metadata is in each encrypted-file transfer's first fragment.
        meta = json.dumps({'name': name, 'prefix': x, 'nonce': nonce.hex(),
                           'size': len(plain), 'sha256': hashlib.sha256(plain).hexdigest()},
                          separators=(',', ':')).encode()
        # A small binary envelope permits arbitrary input file bytes.
        blob = struct.pack('!I', len(meta)) + meta + encrypted
        total = max(1, (len(blob) + CHUNK - 1) // CHUNK)
        if sequence + total > 0xffffffff:
            raise ValueError('Too many packets for 32-bit ESP sequence numbers')
        for index in range(total):
            sequence += 1
            chunk = blob[index * CHUNK:(index + 1) * CHUNK]
            header = struct.pack(ESP_FMT, spi, sequence)
            frag = struct.pack(FRAG_FMT, file_id, index, total)
            body = header + frag + chunk
            tag = hmac.new(mac_key, body, hashlib.sha256).digest()[:TAG_LEN]
            packets.append(Ether(src=SMAC, dst=DMAC)
                           / IP(src=SRC, dst=DST, proto=50, id=sequence % 65536)
                           / Raw(body + tag))
        create_output(out / (name + '.enc'), encrypted)
        print(f'{name}: preserved {x} bytes; {total} ESP-style packets')
    pem = receiver.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    create_output(out / 'receiver_private.pem', pem, private=True)
    now = time.time()
    for i, pkt in enumerate(packets):
        pkt.time = now + i * 0.001
    wrpcap(str(out / 'traffic.pcap'), packets)
    print(f'Generated {len(packets)} packets in {out}')


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
                if magic != MAGIC or version != VERSION:
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
                minimum = struct.calcsize(ESP_FMT) + struct.calcsize(FRAG_FMT) + TAG_LEN
                if len(raw) < minimum:
                    continue
                spi, seq = struct.unpack_from(ESP_FMT, raw)
                file_id, idx, total = struct.unpack_from(FRAG_FMT, raw, struct.calcsize(ESP_FMT))
                streams.setdefault((spi, file_id), []).append((seq, idx, total, raw))
    if init is None or response is None or init[:2] != response[:2]:
        raise ValueError('Incomplete or inconsistent key exchange')
    return init, response, streams


def recover(args):
    init, response, streams = read_capture(args.pcap)
    spi, salt, sender_public = init
    receiver = serialization.load_pem_private_key(Path(args.receiver_key).read_bytes(), password=None)
    if not isinstance(receiver, x25519.X25519PrivateKey) or pub(receiver) != response[2]:
        raise ValueError('Receiver private key does not match PCAP')
    master = derive(receiver, sender_public, salt, spi)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    seen_names = set()
    matches = [(fid, rows) for (s, fid), rows in streams.items() if s == spi]
    if not matches:
        raise ValueError('No ESP packets matching negotiated SPI')
    for fid, rows in matches:
        aes_key, mac_key = file_keys(master, fid)
        parts, total_expected = {}, None
        for seq, idx, total, raw in rows:
            if not seq or total < 1 or idx >= total:
                raise ValueError('Invalid sequence or fragment metadata')
            if total_expected is None:
                total_expected = total
            if total != total_expected:
                raise ValueError('Conflicting total fragment count')
            expected = hmac.new(mac_key, raw[:-TAG_LEN], hashlib.sha256).digest()[:TAG_LEN]
            if not hmac.compare_digest(expected, raw[-TAG_LEN:]):
                raise ValueError(f'Authentication failed on ESP sequence {seq}')
            chunk = raw[struct.calcsize(ESP_FMT) + struct.calcsize(FRAG_FMT):-TAG_LEN]
            if idx in parts and parts[idx] != chunk:
                raise ValueError('Conflicting duplicate fragment')
            parts[idx] = chunk
        if len(parts) != total_expected:
            raise ValueError(f'Missing {total_expected - len(parts)} fragments for {fid.hex()}')
        blob = b''.join(parts[i] for i in range(total_expected))
        if len(blob) < 4:
            raise ValueError('Missing metadata length')
        mlen = struct.unpack_from('!I', blob)[0]
        if mlen > 65536 or len(blob) < 4 + mlen:
            raise ValueError('Invalid metadata length')
        meta = json.loads(blob[4:4 + mlen])
        name = safe_name(meta['name'])
        if name in seen_names:
            raise ValueError('Duplicate original filename in capture')
        seen_names.add(name)
        encrypted = blob[4 + mlen:]
        x = meta['prefix']
        nonce = bytes.fromhex(meta['nonce'])
        if not isinstance(x, int) or x < 0 or x > len(encrypted) or len(nonce) != 16:
            raise ValueError('Invalid prefix or nonce')
        if len(encrypted) != meta['size']:
            raise ValueError('File length mismatch')
        plain = encrypted[:x] + crypt(aes_key, nonce, encrypted[x:])
        if hashlib.sha256(plain).hexdigest() != meta['sha256']:
            raise ValueError('Plaintext hash mismatch')
        if args.mode in ('extract', 'both'):
            create_output(out / (name + '.enc'), encrypted)
        if args.mode in ('decrypt', 'both'):
            create_output(out / name, plain)
        print(f'Recovered {name}: {len(plain)} bytes; {len(parts)} packets; authenticated')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    enc = sub.add_parser('encrypt', help='Encrypt files and generate PCAP')
    enc.add_argument('files', nargs='+')
    enc.add_argument('--out', default='encrypted_output')
    enc.add_argument('--preserve', type=int, help='Preserve exactly this many initial bytes of every input')
    enc.add_argument('--prefix-config', help='JSON mapping of extension to preserved byte count')
    rec = sub.add_parser('recover', help='Extract and/or decrypt all files from PCAP')
    rec.add_argument('pcap')
    rec.add_argument('--receiver-key', required=True)
    rec.add_argument('--out', default='recovered_output')
    rec.add_argument('--mode', choices=['extract', 'decrypt', 'both'], default='both')
    args = parser.parse_args()
    if args.command == 'encrypt':
        generate(args)
    else:
        recover(args)


if __name__ == '__main__':
    main()
