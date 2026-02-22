#!/usr/bin/env python3
"""
Bitcoin Raw Transaction Parser
================================
Parsea una transacción Bitcoin en formato hex crudo y produce un JSON
detallado con cada bloque de datos, su offset, tamaño y valor decodificado.

Uso:
    python3 tx_parser.py <hex>
    echo "<hex>" | python3 tx_parser.py
    python3 tx_parser.py -f <archivo.hex>

Soporta:
    - Transacciones Legacy
    - Transacciones SegWit (BIP141)
    - Taproot (P2TR)
    - Coinbase transactions
"""

import sys
import json
import hashlib
import math
import datetime
import argparse
from typing import Tuple


# ---------------------------------------------------------------------------
# Utilidades criptográficas
# ---------------------------------------------------------------------------

def sha256d(data: bytes) -> bytes:
    """Doble SHA-256 (usado para txid/wtxid)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """SHA-256 seguido de RIPEMD-160 (usado en P2PKH y P2WPKH)."""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Codificación de direcciones — Base58Check (P2PKH, P2SH, P2PK)
# ---------------------------------------------------------------------------

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check_encode(payload: bytes) -> str:
    """Codifica payload (version byte + hash) en Base58Check."""
    checksum = sha256d(payload)[:4]
    data = payload + checksum
    leading = len(data) - len(data.lstrip(b'\x00'))
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = _B58[r] + result
    return '1' * leading + result


# ---------------------------------------------------------------------------
# Codificación de direcciones — Bech32 / Bech32m (P2WPKH, P2WSH, P2TR)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_BECH32_GEN     = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
_BECH32M_CONST  = 0x2bc830a3
_BECH32_CONST   = 1


def _bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list:
    """Convierte un array de enteros de `frombits` bits a `tobits` bits."""
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & ((1 << (frombits + tobits - 1)) - 1)
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes, bech32m: bool = False) -> str:
    """
    Codifica una dirección SegWit nativa en Bech32 (v0) o Bech32m (v1+).

    Args:
        hrp     : 'bc' (mainnet) o 'tb' (testnet)
        witver  : versión witness (0 para P2WPKH/P2WSH, 1 para P2TR)
        witprog : el programa witness (HASH160, SHA256 o x-only pubkey)
        bech32m : True para Taproot (BIP350), False para SegWit v0 (BIP173)
    """
    data = [witver] + _convertbits(witprog, 8, 5)
    const = _BECH32M_CONST if bech32m else _BECH32_CONST
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0] * 6) ^ const
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join(_BECH32_CHARSET[d] for d in data + checksum)


# ---------------------------------------------------------------------------
# Derivación de dirección a partir de scriptPubKey
# ---------------------------------------------------------------------------

def script_to_address(script: bytes,
                       hrp: str = 'bc',
                       p2pkh_ver: bytes = b'\x00',
                       p2sh_ver: bytes = b'\x05'):
    """
    Deriva la dirección Bitcoin del scriptPubKey dado.

    Retorna la dirección como string, o None si el tipo de script no
    tiene una dirección derivable estándar.

    Tipos soportados: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK
    """
    stype = detect_script_type(script)
    try:
        if stype == 'P2PKH':
            # version_byte(1) + HASH160(20) ya están en el script
            return base58check_encode(p2pkh_ver + script[3:23])
        if stype == 'P2SH':
            return base58check_encode(p2sh_ver + script[2:22])
        if stype == 'P2WPKH':
            # OP_0 <20B HASH160> → bech32
            return bech32_encode(hrp, 0, script[2:22], bech32m=False)
        if stype == 'P2WSH':
            # OP_0 <32B SHA256> → bech32
            return bech32_encode(hrp, 0, script[2:34], bech32m=False)
        if stype == 'P2TR':
            # OP_1 <32B x-only-pubkey> → bech32m
            return bech32_encode(hrp, 1, script[2:34], bech32m=True)
        if stype == 'P2PK':
            # No tiene dirección nativa; se derivan la P2PKH equivalente
            pubkey = script[1:-1]
            return base58check_encode(p2pkh_ver + hash160(pubkey))
    except Exception:
        pass
    return None


def pubkey_to_p2wpkh_address(pubkey: bytes, hrp: str = 'bc') -> str:
    """Deriva la dirección P2WPKH de una clave pública comprimida."""
    return bech32_encode(hrp, 0, hash160(pubkey), bech32m=False)


def pubkey_to_p2pkh_address(pubkey: bytes, p2pkh_ver: bytes = b'\x00') -> str:
    """Deriva la dirección P2PKH de una clave pública (comprimida o no)."""
    return base58check_encode(p2pkh_ver + hash160(pubkey))


# ---------------------------------------------------------------------------
# Parsing de primitivos Bitcoin
# ---------------------------------------------------------------------------

def parse_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Parsea un entero de longitud variable (CompactSize / VarInt).
    Retorna (valor, nuevo_offset).
    """
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return int.from_bytes(data[offset + 1:offset + 3], 'little'), offset + 3
    elif first == 0xfe:
        return int.from_bytes(data[offset + 1:offset + 5], 'little'), offset + 5
    else:
        return int.from_bytes(data[offset + 1:offset + 9], 'little'), offset + 9


# ---------------------------------------------------------------------------
# Detección de tipos de script
# ---------------------------------------------------------------------------

def detect_script_type(script: bytes) -> str:
    """Identifica el tipo de script Bitcoin estándar."""
    n = len(script)
    if n == 0:
        return "empty"
    # P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    if n == 25 and script[0:3] == b'\x76\xa9\x14' and script[23:25] == b'\x88\xac':
        return "P2PKH"
    # P2SH: OP_HASH160 <20B> OP_EQUAL
    if n == 23 and script[0:2] == b'\xa9\x14' and script[22] == 0x87:
        return "P2SH"
    # P2WPKH: OP_0 <20B>
    if n == 22 and script[0:2] == b'\x00\x14':
        return "P2WPKH"
    # P2WSH: OP_0 <32B>
    if n == 34 and script[0:2] == b'\x00\x20':
        return "P2WSH"
    # P2TR (Taproot): OP_1 <32B>
    if n == 34 and script[0:2] == b'\x51\x20':
        return "P2TR"
    # P2PK: <pubkey 33 o 65B> OP_CHECKSIG
    if n in (35, 67) and script[-1] == 0xac:
        return "P2PK"
    # OP_RETURN (datos arbitrarios, no gastable)
    if script[0] == 0x6a:
        return "OP_RETURN"
    # Multisig bare: OP_m <pubkeys> OP_n OP_CHECKMULTISIG
    if n > 3 and script[0] in range(0x51, 0x60) and script[-1] == 0xae:
        return "multisig"
    return "nonstandard"


def extract_script_hash(script: bytes):
    """Extrae el hash/clave relevante del script, si es posible."""
    n = len(script)
    if n == 0:
        return None
    if n == 25 and script[0:3] == b'\x76\xa9\x14':
        return script[3:23].hex()  # HASH160 en P2PKH
    if n == 23 and script[0:2] == b'\xa9\x14':
        return script[2:22].hex()  # HASH160 en P2SH
    if n == 22 and script[0:2] == b'\x00\x14':
        return script[2:22].hex()  # HASH160 en P2WPKH
    if n == 34 and script[0:2] in (b'\x00\x20', b'\x51\x20'):
        return script[2:34].hex()  # SHA256 o x-only pubkey
    if n in (35, 67) and script[-1] == 0xac:
        return script[1:-1].hex()  # pubkey en P2PK
    if script[0] == 0x6a and n > 1:
        return script[2:].hex() if n > 2 else ""  # datos OP_RETURN
    return None


def describe_sequence(seq: int) -> str:
    if seq == 0xFFFFFFFF:
        return "final (no RBF, no relative locktime)"
    if seq == 0xFFFFFFFE:
        return "RBF desactivado, locktime relativo habilitado"
    if seq >= 0xFFFFFFFD:
        return "señalización RBF (opt-in)"
    return f"locktime relativo o RBF opt-in (raw: {hex(seq)})"


def describe_locktime(locktime: int) -> str:
    if locktime == 0:
        return "sin locktime"
    if locktime < 500_000_000:
        return f"bloqueado hasta bloque #{locktime}"
    dt = datetime.datetime.utcfromtimestamp(locktime).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"bloqueado hasta {dt}"


# ---------------------------------------------------------------------------
# Decodificación de firmas y elementos witness
# ---------------------------------------------------------------------------

SIGHASH_NAMES = {
    0x00: "SIGHASH_DEFAULT",           # solo Taproot (BIP341)
    0x01: "SIGHASH_ALL",
    0x02: "SIGHASH_NONE",
    0x03: "SIGHASH_SINGLE",
    0x81: "SIGHASH_ALL|ANYONECANPAY",
    0x82: "SIGHASH_NONE|ANYONECANPAY",
    0x83: "SIGHASH_SINGLE|ANYONECANPAY",
}


def decode_der_sig(raw: bytes):
    """
    Decodifica una firma ECDSA en formato DER de Bitcoin.

    Estructura:
      0x30  [seq_len]
        0x02  [r_len]  [r bytes]
        0x02  [s_len]  [s bytes]
      [sighash_type]        ← byte añadido por Bitcoin (fuera del DER estándar)

    Retorna dict con los campos decodificados, o None si no es DER válido.
    """
    n = len(raw)
    if n < 9 or raw[0] != 0x30:
        return None
    try:
        seq_len = raw[1]
        # total = 0x30 (1) + seq_len (1) + payload (seq_len) + sighash (1)
        if seq_len + 3 != n:
            return None
        pos = 2
        # --- r ---
        if raw[pos] != 0x02:
            return None
        r_len = raw[pos + 1]
        if r_len == 0 or pos + 2 + r_len > n:
            return None
        pos += 2
        r_bytes = raw[pos:pos + r_len]
        pos += r_len
        # --- s ---
        if raw[pos] != 0x02:
            return None
        s_len = raw[pos + 1]
        if s_len == 0 or pos + 2 + s_len > n:
            return None
        pos += 2
        s_bytes = raw[pos:pos + s_len]
        pos += s_len
        # --- sighash ---
        sighash = raw[pos]

        # Quitar el 0x00 de padding DER si está presente (high-bit protection)
        r_clean = r_bytes[1:] if (r_bytes[0] == 0x00 and len(r_bytes) > 1) else r_bytes
        s_clean = s_bytes[1:] if (s_bytes[0] == 0x00 and len(s_bytes) > 1) else s_bytes

        return {
            "algorithm": "ECDSA",
            "encoding": "DER",
            "r": r_clean.hex(),
            "r_der_padded": r_bytes[0] == 0x00,
            "s": s_clean.hex(),
            "s_der_padded": s_bytes[0] == 0x00,
            "sighash_byte": hex(sighash),
            "sighash_type": SIGHASH_NAMES.get(sighash, f"desconocido ({hex(sighash)})"),
        }
    except (IndexError, ValueError):
        return None


def decode_schnorr_sig(raw: bytes):
    """
    Decodifica una firma Schnorr de Taproot (BIP340).

    Estructura:
      [32 bytes]  R (coordenada x del punto nonce)
      [32 bytes]  s (escalar)
      [1 byte]    sighash_type  ← solo presente si ≠ SIGHASH_DEFAULT

    64 bytes → SIGHASH_DEFAULT implícito
    65 bytes → sighash explícito en el último byte
    """
    n = len(raw)
    if n == 64:
        sighash = 0x00
        sig_bytes = raw
    elif n == 65:
        sighash = raw[64]
        sig_bytes = raw[:64]
    else:
        return None

    return {
        "algorithm": "Schnorr",
        "encoding": "BIP340",
        "R": sig_bytes[0:32].hex(),
        "s": sig_bytes[32:64].hex(),
        "sighash_byte": hex(sighash),
        "sighash_type": SIGHASH_NAMES.get(sighash, f"desconocido ({hex(sighash)})"),
    }


def classify_witness_item(raw: bytes,
                           hrp: str = 'bc',
                           p2pkh_ver: bytes = b'\x00') -> dict:
    """
    Identifica el tipo de un item del stack witness y lo decodifica si es posible.
    Para claves públicas también deriva las direcciones P2WPKH y P2PKH.
    """
    n = len(raw)
    if n == 0:
        return {"item_type": "empty"}

    # Firma ECDSA DER (comienza con 0x30, rango típico 71-73 bytes)
    if raw[0] == 0x30 and 9 <= n <= 73:
        decoded = decode_der_sig(raw)
        if decoded:
            return {"item_type": "ECDSA_signature", "decoded": decoded}

    # Firma Schnorr Taproot (BIP340): 64 o 65 bytes
    if n in (64, 65):
        decoded = decode_schnorr_sig(raw)
        if decoded:
            return {"item_type": "Schnorr_signature", "decoded": decoded}

    # Clave pública comprimida (33 bytes, prefijo 0x02 o 0x03)
    if n == 33 and raw[0] in (0x02, 0x03):
        try:
            p2wpkh_addr = pubkey_to_p2wpkh_address(raw, hrp)
            p2pkh_addr  = pubkey_to_p2pkh_address(raw, p2pkh_ver)
        except Exception:
            p2wpkh_addr = p2pkh_addr = None
        return {
            "item_type": "compressed_pubkey",
            "decoded": {
                "parity": "par (even)" if raw[0] == 0x02 else "impar (odd)",
                "x": raw[1:].hex(),
                "p2wpkh_address": p2wpkh_addr,
                "p2pkh_address":  p2pkh_addr,
            },
        }

    # Clave pública sin comprimir (65 bytes, prefijo 0x04)
    if n == 65 and raw[0] == 0x04:
        try:
            p2pkh_addr = pubkey_to_p2pkh_address(raw, p2pkh_ver)
        except Exception:
            p2pkh_addr = None
        return {
            "item_type": "uncompressed_pubkey",
            "decoded": {
                "x": raw[1:33].hex(),
                "y": raw[33:65].hex(),
                "p2pkh_address": p2pkh_addr,
            },
        }

    # Clave x-only de Taproot (32 bytes — output key o internal key)
    if n == 32:
        try:
            p2tr_addr = bech32_encode(hrp, 1, raw, bech32m=True)
        except Exception:
            p2tr_addr = None
        return {
            "item_type": "x_only_pubkey",
            "decoded": {
                "x": raw.hex(),
                "p2tr_address": p2tr_addr,
            },
        }

    # Script de redención / witness script (items largos sin prefijo de firma)
    if n > 1:
        stype = detect_script_type(raw)
        return {
            "item_type": "script",
            "script_type": stype,
        }

    return {"item_type": "data"}


# ---------------------------------------------------------------------------
# Parser principal
# ---------------------------------------------------------------------------

def parse_tx(raw_hex: str, network: str = 'mainnet') -> dict:
    """
    Parsea una transacción Bitcoin en formato hex crudo.

    Args:
        raw_hex : string hexadecimal de la transacción
        network : 'mainnet' (default) o 'testnet'
    """
    if network == 'testnet':
        hrp       = 'tb'
        p2pkh_ver = b'\x6f'
        p2sh_ver  = b'\xc4'
    else:
        hrp       = 'bc'
        p2pkh_ver = b'\x00'
        p2sh_ver  = b'\x05'

    raw_hex = raw_hex.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    data = bytes.fromhex(raw_hex)
    offset = 0
    blocks = []

    # --- helpers internos ---

    def add_raw(field: str, start: int, end: int, **extra) -> bytes:
        raw = data[start:end]
        b = {
            "field": field,
            "offset_bytes": start,
            "size_bytes": end - start,
            "hex": raw.hex(),
        }
        b.update(extra)
        blocks.append(b)
        return raw

    def read_bytes(field: str, n: int, **extra) -> bytes:
        nonlocal offset
        start = offset
        offset += n
        return add_raw(field, start, offset, **extra)

    def read_varint(field: str) -> int:
        nonlocal offset
        start = offset
        value, offset = parse_varint(data, offset)
        add_raw(field, start, offset, value=value)
        return value

    # -----------------------------------------------------------------------
    # VERSION  (4 bytes, little-endian)
    # -----------------------------------------------------------------------
    raw = read_bytes("version", 4)
    version = int.from_bytes(raw, 'little')
    blocks[-1]["value"] = version

    # -----------------------------------------------------------------------
    # DETECCIÓN SEGWIT (BIP141)
    # marker=0x00, flag=0x01 justo después de la versión
    # -----------------------------------------------------------------------
    segwit = (len(data) > offset + 1
              and data[offset] == 0x00
              and data[offset + 1] == 0x01)

    if segwit:
        read_bytes("segwit_marker", 1, value=0,
                   note="Byte marcador SegWit (0x00) — BIP141")
        read_bytes("segwit_flag", 1, value=1,
                   note="Byte flag SegWit (0x01) — BIP141")

    # Punto de inicio de los datos no-witness (para cálculo de txid)
    non_witness_start = offset

    # -----------------------------------------------------------------------
    # INPUTS
    # -----------------------------------------------------------------------
    in_count = read_varint("input_count")

    for i in range(in_count):
        # Previous TXID: 32 bytes almacenados little-endian → mostrar reversed
        raw = read_bytes(f"inputs[{i}].prev_txid", 32)
        prev_txid_disp = raw[::-1].hex()
        blocks[-1]["value"] = prev_txid_disp

        # Previous output index
        raw = read_bytes(f"inputs[{i}].prev_vout", 4)
        prev_vout = int.from_bytes(raw, 'little')
        blocks[-1]["value"] = prev_vout

        is_coinbase = (prev_txid_disp == "0" * 64 and prev_vout == 0xFFFFFFFF)

        # scriptSig length (varint)
        sig_len = read_varint(f"inputs[{i}].script_sig_length")

        # scriptSig
        raw = read_bytes(f"inputs[{i}].script_sig", sig_len)
        if is_coinbase:
            blocks[-1]["script_type"] = "coinbase"
            # BIP34: primer byte = longitud, luego altura del bloque en little-endian
            if sig_len >= 2:
                try:
                    hl = raw[0]
                    height = int.from_bytes(raw[1:1 + hl], 'little')
                    blocks[-1]["coinbase_block_height"] = height
                except Exception:
                    pass
        else:
            stype = detect_script_type(raw)
            blocks[-1]["script_type"] = stype
            h = extract_script_hash(raw)
            if h:
                blocks[-1]["script_hash_or_key"] = h

        # Sequence (4 bytes, little-endian)
        raw = read_bytes(f"inputs[{i}].sequence", 4)
        seq = int.from_bytes(raw, 'little')
        blocks[-1]["value"] = hex(seq)
        blocks[-1]["note"] = describe_sequence(seq)

    # -----------------------------------------------------------------------
    # OUTPUTS
    # -----------------------------------------------------------------------
    out_count = read_varint("output_count")

    for i in range(out_count):
        # Value en satoshis (8 bytes, little-endian)
        raw = read_bytes(f"outputs[{i}].value", 8)
        sats = int.from_bytes(raw, 'little')
        blocks[-1]["value"] = {
            "satoshis": sats,
            "btc": round(sats / 1e8, 8),
        }

        # scriptPubKey length
        pk_len = read_varint(f"outputs[{i}].script_pubkey_length")

        # scriptPubKey
        raw = read_bytes(f"outputs[{i}].script_pubkey", pk_len)
        stype = detect_script_type(raw)
        blocks[-1]["script_type"] = stype
        h = extract_script_hash(raw)
        if h:
            blocks[-1]["script_hash_or_key"] = h
        addr = script_to_address(raw, hrp=hrp, p2pkh_ver=p2pkh_ver, p2sh_ver=p2sh_ver)
        if addr:
            blocks[-1]["address"] = addr

    # Fin de datos no-witness
    non_witness_end = offset

    # -----------------------------------------------------------------------
    # WITNESS DATA (solo SegWit)
    # Un stack de items por cada input, en el mismo orden
    # -----------------------------------------------------------------------
    if segwit:
        for i in range(in_count):
            stack_count = read_varint(f"inputs[{i}].witness_stack_count")
            for j in range(stack_count):
                wit_len = read_varint(f"inputs[{i}].witness[{j}].length")
                if wit_len > 0:
                    raw = read_bytes(f"inputs[{i}].witness[{j}].data", wit_len)
                    classification = classify_witness_item(raw, hrp=hrp, p2pkh_ver=p2pkh_ver)
                    blocks[-1].update(classification)

    # -----------------------------------------------------------------------
    # LOCKTIME (4 bytes, little-endian)
    # -----------------------------------------------------------------------
    raw = read_bytes("locktime", 4)
    locktime = int.from_bytes(raw, 'little')
    blocks[-1]["value"] = locktime
    blocks[-1]["note"] = describe_locktime(locktime)

    # Verificar que consumimos exactamente todos los bytes
    if offset != len(data):
        raise ValueError(
            f"Bytes sin parsear: se consumieron {offset} de {len(data)} bytes. "
            f"La transacción puede estar mal formada o truncada."
        )

    # -----------------------------------------------------------------------
    # TXID / WTXID y métricas
    # -----------------------------------------------------------------------
    if segwit:
        # txid usa serialización sin witness: version | inputs+outputs | locktime
        non_witness_data = (
            data[:4]
            + data[non_witness_start:non_witness_end]
            + data[-4:]
        )
        txid = sha256d(non_witness_data)[::-1].hex()
        wtxid = sha256d(data)[::-1].hex()
        base_size = len(non_witness_data)
        total_size = len(data)
        weight = base_size * 3 + total_size
        vsize = math.ceil(weight / 4)
    else:
        txid = sha256d(data)[::-1].hex()
        wtxid = txid
        total_size = len(data)
        base_size = total_size
        weight = total_size * 4
        vsize = total_size

    return {
        "txid": txid,
        "wtxid": wtxid,
        "size": total_size,
        "vsize": vsize,
        "weight": weight,
        "version": version,
        "segwit": segwit,
        "input_count": in_count,
        "output_count": out_count,
        "locktime": locktime,
        "network": network,
        "blocks": blocks,
    }


# ---------------------------------------------------------------------------
# Lógica del resumen (--summary)
# ---------------------------------------------------------------------------

def _scriptsig_p2pkh_pubkey(sig_hex: str):
    """
    Intenta extraer la clave pública de un scriptSig P2PKH.
    Formato: <push_sig> <sig_bytes> <push_pubkey> <pubkey_bytes>
    Retorna los bytes de la pubkey o None si no es parseable.
    """
    try:
        raw = bytes.fromhex(sig_hex)
        if len(raw) < 2:
            return None
        sig_len = raw[0]                   # primer byte = OP_DATA (longitud de la firma)
        pos = 1 + sig_len
        if pos >= len(raw):
            return None
        pk_len = raw[pos]                  # OP_DATA para la pubkey
        pos += 1
        pk = raw[pos: pos + pk_len]
        if len(pk) != pk_len or pk_len not in (33, 65):
            return None
        if pk_len == 33 and pk[0] not in (0x02, 0x03):
            return None
        if pk_len == 65 and pk[0] != 0x04:
            return None
        return pk
    except Exception:
        return None


def _scriptsig_p2sh_wpkh_hash(sig_hex: str):
    """
    Detecta P2SH-P2WPKH: scriptSig = 0x16 0x00 0x14 <20 bytes hash160>.
    Retorna el hash160 (bytes) o None.
    """
    try:
        raw = bytes.fromhex(sig_hex)
        # 23 bytes: 0x16 (push 22) + 0x00 0x14 (OP_0 + push 20) + 20 bytes hash
        if len(raw) == 23 and raw[0] == 0x16 and raw[1:3] == b'\x00\x14':
            return raw[3:23]
        return None
    except Exception:
        return None


def _infer_input(i: int, by_field: dict, hrp: str, p2pkh_ver: bytes) -> dict:
    """
    Infiere dirección de gasto, tipo y datos relevantes del input i.
    Retorna un dict con los campos del input para el summary.
    """
    prev_txid  = by_field.get(f"inputs[{i}].prev_txid",  {}).get("value", "?")
    prev_vout  = by_field.get(f"inputs[{i}].prev_vout",  {}).get("value", "?")
    seq_block  = by_field.get(f"inputs[{i}].sequence",   {})
    sig_block  = by_field.get(f"inputs[{i}].script_sig", {})
    wit_count  = by_field.get(f"inputs[{i}].witness_stack_count", {}).get("value", 0)

    seq_val = int(seq_block.get("value", "0xffffffff"), 16)
    rbf     = seq_val <= 0xFFFFFFFD

    base = {
        "index":     i,
        "prev_txid": prev_txid,
        "prev_vout": prev_vout,
        "sequence":  seq_block.get("value"),
        "rbf":       rbf,
    }

    is_coinbase = (sig_block.get("script_type") == "coinbase")
    if is_coinbase:
        base["address"]      = "COINBASE"
        base["address_type"] = "coinbase"
        height = sig_block.get("coinbase_block_height")
        if height is not None:
            base["coinbase_block_height"] = height
        return base

    w0 = by_field.get(f"inputs[{i}].witness[0].data", {})
    w1 = by_field.get(f"inputs[{i}].witness[1].data", {})

    # ── P2WPKH nativo: witness = [ECDSA_sig, compressed_pubkey] ──────────
    if (wit_count == 2
            and w0.get("item_type") == "ECDSA_signature"
            and w1.get("item_type") == "compressed_pubkey"):
        dec  = w1.get("decoded", {})
        base["address"]      = dec.get("p2wpkh_address")
        base["address_type"] = "P2WPKH"
        base["pubkey"]       = w1.get("hex")
        return base

    # ── P2TR key-path: witness = [Schnorr_sig], scriptSig vacío ──────────
    if wit_count == 1 and w0.get("item_type") == "Schnorr_signature":
        base["address"]      = None
        base["address_type"] = "P2TR key-path"
        base["address_note"] = "requiere lookup del UTXO anterior para derivar address"
        base["schnorr_sig"]  = {
            "R": w0.get("decoded", {}).get("R"),
            "s": w0.get("decoded", {}).get("s"),
            "sighash_type": w0.get("decoded", {}).get("sighash_type"),
        }
        return base

    # ── P2TR script-path: witness = [...items, script, control_block] ─────
    if wit_count >= 2:
        # El último item suele ser el control block (≥33 bytes, prefijo 0xc0/0xc1)
        last_block = by_field.get(f"inputs[{i}].witness[{wit_count-1}].data", {})
        last_hex   = last_block.get("hex", "")
        if last_hex and len(last_hex) >= 2 and int(last_hex[:2], 16) in range(0xc0, 0xd0):
            # extraer internal_key del control block (bytes 1-32)
            ctrl = bytes.fromhex(last_hex)
            internal_key = ctrl[1:33].hex() if len(ctrl) >= 33 else None
            base["address"]       = None
            base["address_type"]  = "P2TR script-path"
            base["address_note"]  = "requiere calcular taptweak para derivar address"
            base["internal_key"]  = internal_key
            return base

    # ── P2SH-P2WPKH (wrapped SegWit): scriptSig tiene el redeem script ───
    sig_hex = sig_block.get("hex", "")
    h160 = _scriptsig_p2sh_wpkh_hash(sig_hex)
    if h160 and wit_count == 2 and w1.get("item_type") == "compressed_pubkey":
        addr = base58check_encode(b'\x05' + hash160(bytes.fromhex(sig_hex[2:]))) if sig_hex else None
        # La dirección P2SH viene del hash del redeem script
        try:
            redeem = bytes.fromhex(sig_hex)[1:]   # quitar el OP_DATA inicial
            addr   = base58check_encode(b'\x05' + hash160(redeem))
        except Exception:
            addr = None
        base["address"]      = addr
        base["address_type"] = "P2SH-P2WPKH"
        base["pubkey"]       = w1.get("hex")
        return base

    # ── P2PKH legacy: scriptSig tiene <sig><pubkey> ───────────────────────
    if sig_hex and wit_count == 0:
        pk = _scriptsig_p2pkh_pubkey(sig_hex)
        if pk:
            try:
                addr = pubkey_to_p2pkh_address(pk, p2pkh_ver)
            except Exception:
                addr = None
            base["address"]      = addr
            base["address_type"] = "P2PKH"
            base["pubkey"]       = pk.hex()
            return base

    # ── Fallback ──────────────────────────────────────────────────────────
    base["address"]      = None
    base["address_type"] = "desconocido"
    base["address_note"] = "requiere lookup del UTXO anterior"
    return base


def build_summary(result: dict) -> dict:
    """
    Construye un resumen legible de lo más relevante de la transacción:
    - Metadatos (txid, tamaños, red, flags)
    - Inputs con dirección de gasto inferida (donde sea posible)
    - Outputs con dirección y cantidad
    - Total enviado, fee (si calculable)
    """
    network   = result.get("network", "mainnet")
    hrp       = "tb"    if network == "testnet" else "bc"
    p2pkh_ver = b'\x6f' if network == "testnet" else b'\x00'

    by_field = {b["field"]: b for b in result["blocks"]}

    # ── Inputs ───────────────────────────────────────────────────────────
    inputs_out = [
        _infer_input(i, by_field, hrp, p2pkh_ver)
        for i in range(result["input_count"])
    ]

    rbf_global = any(inp.get("rbf", False) for inp in inputs_out
                     if inp.get("address_type") != "coinbase")

    # ── Outputs ──────────────────────────────────────────────────────────
    outputs_out = []
    total_out_sats = 0
    for i in range(result["output_count"]):
        val = by_field.get(f"outputs[{i}].value", {}).get("value", {})
        pk  = by_field.get(f"outputs[{i}].script_pubkey", {})
        sats = val.get("satoshis", 0) if isinstance(val, dict) else 0
        total_out_sats += sats
        outputs_out.append({
            "index":             i,
            "address":           pk.get("address"),
            "address_type":      pk.get("script_type"),
            "amount_satoshis":   sats,
            "amount_btc":        round(sats / 1e8, 8),
        })

    # ── Locktime ─────────────────────────────────────────────────────────
    lt_block = by_field.get("locktime", {})

    # ── Tipo de tx ───────────────────────────────────────────────────────
    input_types = list({inp.get("address_type") for inp in inputs_out
                        if inp.get("address_type") not in (None, "desconocido")})
    output_types = list({o["address_type"] for o in outputs_out if o["address_type"]})
    is_coinbase  = any(inp.get("address_type") == "coinbase" for inp in inputs_out)

    if is_coinbase:
        tx_type = "coinbase"
    elif result["segwit"]:
        # Inferir tipo principal por los inputs
        if any("P2TR" in (t or "") for t in input_types):
            tx_type = "Taproot"
        elif any("P2WPKH" in (t or "") for t in input_types):
            tx_type = "SegWit (P2WPKH)"
        elif any("P2SH-P2WPKH" in (t or "") for t in input_types):
            tx_type = "SegWit wrapped (P2SH-P2WPKH)"
        else:
            tx_type = "SegWit"
    else:
        tx_type = "Legacy"

    return {
        "txid":    result["txid"],
        "wtxid":   result["wtxid"],
        "network": network,
        "tx_type": tx_type,
        "version": result["version"],
        "size": {
            "bytes":   result["size"],
            "vbytes":  result["vsize"],
            "weight":  result["weight"],
        },
        "locktime": {
            "value":       result["locktime"],
            "description": lt_block.get("note", ""),
        },
        "rbf_opt_in":    rbf_global,
        "input_count":   result["input_count"],
        "output_count":  result["output_count"],
        "inputs":        inputs_out,
        "outputs":       outputs_out,
        "total_output": {
            "satoshis": total_out_sats,
            "btc":      round(total_out_sats / 1e8, 8),
        },
        "fee": {
            "satoshis": None,
            "btc":      None,
            "note":     (
                "No calculable: los valores de los inputs requieren "
                "lookup de UTXOs en la blockchain"
            ),
        },
        "spending_address_types": input_types,
        "output_address_types":   output_types,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parsea una transacción Bitcoin raw (hex) y produce JSON detallado.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 tx_parser.py 0100000001...
  echo "0100000001..." | python3 tx_parser.py
  python3 tx_parser.py -f tx.hex
        """,
    )
    parser.add_argument(
        "hex", nargs="?",
        help="Transacción en hex crudo (raw tx). Si se omite, se lee de stdin."
    )
    parser.add_argument(
        "-f", "--file", metavar="FILE",
        help="Leer el hex desde un archivo."
    )
    parser.add_argument(
        "--compact", action="store_true",
        help="Salida JSON compacta (sin indentación)."
    )
    parser.add_argument(
        "--testnet", action="store_true",
        help="Usar prefijos de testnet para las direcciones (tb1, m/n, 2...)."
    )
    parser.add_argument(
        "-s", "--summary", action="store_true",
        help=(
            "Mostrar solo el resumen de la transacción: addresses, montos, "
            "fees y flags. Omite el array 'blocks' de bajo nivel."
        ),
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file) as fh:
            raw_hex = fh.read()
    elif args.hex:
        raw_hex = args.hex
    else:
        if sys.stdin.isatty():
            print("Introduce el hex de la transacción y presiona Enter + Ctrl-D:",
                  file=sys.stderr)
        raw_hex = sys.stdin.read()

    network = 'testnet' if args.testnet else 'mainnet'
    try:
        result = parse_tx(raw_hex, network=network)
        if args.summary:
            output = build_summary(result)
        else:
            output = result
        indent = None if args.compact else 2
        print(json.dumps(output, indent=indent, ensure_ascii=False))
    except ValueError as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Error inesperado: {e}"}, indent=2), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
