# Quant (QNT) — core node

Post-quantum proof-of-work cryptocurrency. This repository is the full node (`quantd`), the
command-line client (`quant-cli`) and the shared library used by the desktop client
([quant-qt](https://github.com/tehrealaju-svg/quant-qt)) and the Termux phone wallet
([quant-termux](https://github.com/tehrealaju-svg/quant-termux)).

* **Falcon-512** signatures + a **SPHINCS+** backup key inside every address
* **BLAKE3** hashing and proof-of-work, 2-minute blocks, difficulty adjusted every block
* **50 QNT** reward, halving every **8 years**, ~210.24M max, 10 decimal places, no premine
* **Signature pruning** — signatures deleted after ~1 week; ~116 bytes stored per payment
* **No servers** — peers found through the BitTorrent DHT (IPv4 + IPv6), LAN broadcast and saved peers
* **Works behind Starlink / mobile CGNAT** — IPv6 makes your node reachable without port forwarding
* Minimum fee 0.00001 QNT/KB (≈0.00002 QNT per payment), minimum amount 0.000001 QNT

Design: [docs/WHITEPAPER.md](docs/WHITEPAPER.md) · Mainnet launch: [LAUNCH.md](LAUNCH.md)

> ⚠️ Experimental, unaudited software. Mainnet is not launched; everything defaults to testnet.

## Build

Requires CMake ≥ 3.16 and a C++20 compiler (GCC 11+, Clang 14+). All dependencies are vendored.

**Windows (MinGW-w64):**
```
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j
```

**Linux / Raspberry Pi OS (64-bit) / Termux:**
```
sudo apt install build-essential cmake        # Termux: pkg install clang cmake
cmake -S . -B build
cmake --build build -j4
```
On a Pi, BLAKE3 automatically uses ARM NEON.

Run the tests: `build/quant-tests`

## Run a node

```
quantd -createwallet -mine=2        # testnet node + wallet + 2 mining threads
quant-cli getinfo
quant-cli getnewaddress
quant-cli send tqnt1... 1.25
quant-cli help
```

Useful options: `-addnode=IP:PORT`, `-noprune` (archive), `-nodht`, `-nolan`, `-noupnp`,
`-regtest` (private instant-block chain), `-datadir=DIR`. Data lives in `%APPDATA%\Quant`
(Windows) or `~/.quant` (Linux/Pi).

### Raspberry Pi as an always-on node

```
git clone https://github.com/tehrealaju-svg/quant-core && cd quant-core
cmake -S . -B build && cmake --build build -j4
./build/quantd -createwallet
```
Forward TCP+UDP port **17337** (testnet) / **7337** (mainnet) on your router if UPnP isn't
available, so other nodes can reach yours. `contrib/quantd.service` runs it at boot with systemd.

## Ports

| | P2P (TCP+UDP) | RPC (localhost) | LAN discovery (UDP) |
|---|---|---|---|
| mainnet | 7337 | 7338 | 7339 |
| testnet | 17337 | 17338 | 17339 |
| regtest | 27337 | 27338 | 27339 |

## License

MIT. Vendored: BLAKE3 (CC0/Apache-2.0), PQClean Falcon & SPHINCS+ (MIT/CC0),
miniupnpc (BSD-3), nlohmann/json (MIT), BIP-39 wordlist (MIT).
