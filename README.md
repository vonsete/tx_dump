# tx_dump

Bitcoin raw transaction parser. Decodifica una transacción en formato hex crudo y produce un JSON detallado con cada bloque de datos, su offset, tamaño, valor interpretado y — donde aplica — la dirección Bitcoin derivada.

## Características

- **Formatos soportados**: Legacy, SegWit (BIP141), Taproot (P2TR), coinbase
- **Cada campo expone**: offset en bytes, tamaño, hex crudo y valor decodificado
- **Tipos de script**: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, OP_RETURN, multisig
- **Firmas ECDSA DER**: extrae `r`, `s` y `sighash_type` de cada firma del witness
- **Firmas Schnorr** (BIP340): extrae `R`, `s` y `sighash_type` para Taproot
- **Direcciones**: derivación automática de Base58Check (P2PKH/P2SH), Bech32 (P2WPKH/P2WSH) y Bech32m (P2TR)
- **`--summary`**: resumen compacto con addresses origen/destino, montos e información de fees
- **Métricas**: `txid`, `wtxid`, `size`, `vsize`, `weight`
- **Mainnet y testnet** (`--testnet`)
- Sin dependencias externas — solo librería estándar de Python

## Requisitos

Python 3.9+

## Instalación

```bash
git clone https://github.com/vonsete/tx_dump.git
cd tx_dump
```

## Uso

```bash
# Hex como argumento
python3 tx_parser.py <hex>

# Desde stdin
echo "<hex>" | python3 tx_parser.py

# Desde archivo
python3 tx_parser.py -f tx.hex

# Resumen legible (sin el array de bloques)
python3 tx_parser.py --summary <hex>

# Direcciones en formato testnet
python3 tx_parser.py --testnet <hex>

# Salida compacta (sin indentación)
python3 tx_parser.py --compact <hex>
```

## Salida — modo completo (por defecto)

Cada campo de la transacción aparece como un objeto dentro del array `blocks`:

```json
{
  "txid": "e02b8801c76a...",
  "wtxid": "0e15e28f10c2...",
  "size": 1418,
  "vsize": 695,
  "weight": 2777,
  "version": 2,
  "segwit": true,
  "input_count": 9,
  "output_count": 2,
  "locktime": 937356,
  "blocks": [
    {
      "field": "version",
      "offset_bytes": 0,
      "size_bytes": 4,
      "hex": "02000000",
      "value": 2
    },
    {
      "field": "inputs[0].witness[0].data",
      "offset_bytes": 453,
      "size_bytes": 71,
      "hex": "304402...",
      "item_type": "ECDSA_signature",
      "decoded": {
        "algorithm": "ECDSA",
        "encoding": "DER",
        "r": "4636944527f35c46...",
        "s": "352232c20acffec4...",
        "sighash_byte": "0x1",
        "sighash_type": "SIGHASH_ALL"
      }
    },
    {
      "field": "inputs[0].witness[1].data",
      "offset_bytes": 525,
      "size_bytes": 33,
      "hex": "02bf1797c0...",
      "item_type": "compressed_pubkey",
      "decoded": {
        "parity": "par (even)",
        "x": "bf1797c04e58e213...",
        "p2wpkh_address": "bc1qjj2reu98y22esyrvf82sujhndtjac87nstudd4",
        "p2pkh_address": "1EYcb9ktvUvwCUzQTgTK2qu3Z41Joy9v8Y"
      }
    },
    {
      "field": "outputs[0].script_pubkey",
      "offset_bytes": 386,
      "size_bytes": 34,
      "hex": "512095d2c009...",
      "script_type": "P2TR",
      "address": "bc1pjhfvqz04lwwmcjuvzpercts884l2s62ew8ctjj2d7wlue0s6hzyqe048tu"
    }
  ]
}
```

## Salida — modo `--summary`

```bash
python3 tx_parser.py --summary <hex>
```

```json
{
  "txid": "e02b8801c76a...",
  "network": "mainnet",
  "tx_type": "SegWit (P2WPKH)",
  "version": 2,
  "size": { "bytes": 1418, "vbytes": 695, "weight": 2777 },
  "locktime": { "value": 937356, "description": "bloqueado hasta bloque #937356" },
  "rbf_opt_in": true,
  "inputs": [
    {
      "index": 0,
      "prev_txid": "ebba4a2b...",
      "prev_vout": 642,
      "address": "bc1qjj2reu98y22esyrvf82sujhndtjac87nstudd4",
      "address_type": "P2WPKH",
      "pubkey": "02bf1797c04e58e2..."
    }
  ],
  "outputs": [
    {
      "index": 0,
      "address": "bc1pjhfvqz04lwwmcjuvzpercts884l2s62ew8ctjj2d7wlue0s6hzyqe048tu",
      "address_type": "P2TR",
      "amount_satoshis": 1000000,
      "amount_btc": 0.01
    }
  ],
  "total_output": { "satoshis": 1114265, "btc": 0.01114265 },
  "fee": {
    "satoshis": null,
    "btc": null,
    "note": "No calculable: los valores de los inputs requieren lookup de UTXOs en la blockchain"
  }
}
```

> **Nota sobre fees**: la transacción raw no incluye los valores de los UTXOs de entrada. Para calcular la comisión es necesario consultar la blockchain y obtener el valor de cada output referenciado por los inputs.

## Tipos de script detectados

| Tipo | Descripción |
|------|-------------|
| `P2PKH` | Pay-to-Public-Key-Hash (legacy) |
| `P2SH` | Pay-to-Script-Hash |
| `P2WPKH` | Pay-to-Witness-Public-Key-Hash (SegWit v0 nativo) |
| `P2WSH` | Pay-to-Witness-Script-Hash (SegWit v0 nativo) |
| `P2TR` | Pay-to-Taproot (SegWit v1, BIP341) |
| `P2PK` | Pay-to-Public-Key (obsoleto) |
| `OP_RETURN` | Datos arbitrarios no gastables |
| `multisig` | Multisig bare |
| `nonstandard` | Script no estándar |
| `coinbase` | Script de entrada coinbase |

## Lógica de inferencia de dirección de origen (`--summary`)

El parser infiere la dirección gastadora de cada input a partir de los datos disponibles en la propia transacción:

| Tipo detectado | Método |
|----------------|--------|
| **P2WPKH** | `HASH160(pubkey)` del witness → bech32 |
| **P2PKH** | pubkey del scriptSig → base58check |
| **P2SH-P2WPKH** | redeem script del scriptSig + witness pubkey |
| **P2TR key-path** | solo contiene firma Schnorr, sin pubkey expuesta → `null` |
| **P2TR script-path** | internal key del control block extraído → `null` |

## Campos del summary por input

| Campo | Descripción |
|-------|-------------|
| `prev_txid` | TXID del UTXO gastado |
| `prev_vout` | Índice del output referenciado |
| `address` | Dirección de gasto inferida (o `null`) |
| `address_type` | Tipo del UTXO gastado |
| `pubkey` | Clave pública usada (si aplica) |
| `schnorr_sig` | `R`, `s` y `sighash_type` para Taproot key-path |
| `rbf` | `true` si `sequence ≤ 0xFFFFFFFD` |

## Sighash types soportados

`SIGHASH_DEFAULT`, `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE` y sus variantes `|ANYONECANPAY`.

## Licencia

MIT
