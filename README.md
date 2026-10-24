# Quant (QNT) — core node

Post-quantum proof-of-work cryptocurrency. This repository is the full node (`quantd`), the
command-line client (`quant-cli`) and the shared library used by the desktop client
([quant-qt](https://github.com/tehrealaju-svg/quant-qt)) and the Termux phone wallet
([quant-termux](https://github.com/tehrealaju-svg/quant-termux)).

* **Falcon-512** (NIST post-quantum) signatures
* **BLAKE3** hashing and proof-of-work, 2-minute blocks, difficulty adjusted every block
* **Smooth emission**: ~8.9 QNT/block decaying to a permanent **3.5 QNT/block** tail (~30 years, ~45.6M issued),
  no halvings, no premine, **no developer fee**, 10 decimal places
* **Tokens + on-chain AMM** — anyone can create a token (just the normal fee); constant-product
  QNT/token pools with a 0.3% fee that goes entirely to liquidity providers
* **State snapshots** — every ~2 weeks the full state is committed in a block header; new nodes
  download that snapshot and only the blocks after it (fast sync)
* **Signature pruning** — signatures deleted after ~1 week; ~116 bytes stored per payment
* **No servers** — peers found through the BitTorrent DHT (IPv4 + IPv6), LAN broadcast and saved peers
* **Works behind Starlink / mobile CGNAT** — IPv6 makes your node reachable without port forwarding
* Minimum fee 0.00001 QNT/KB (≈0.00002 QNT per payment), minimum amount 0.000001 QNT

White paper: [docs/quant-whitepaper.pdf](docs/quant-whitepaper.pdf) · Mainnet launch: [LAUNCH.md](LAUNCH.md)

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

Useful options: `-addnode=IP:PORT`, `-noprune` (archive), `-nofastsync` (verify from genesis), `-nodht`, `-nolan`, `-noupnp`,
`-regtest` (private instant-block chain), `-datadir=DIR`. Data lives in `%APPDATA%\Quant`
(Windows) or `~/.quant` (Linux/Pi).

### Tokens and trading

```
quant-cli createtoken DOGE2 "Doge Two" 1000000        # free: only the normal tx fee
quant-cli addliquidity DOGE2 100 500000               # open the QNT/DOGE2 pool
quant-cli quote DOGE2 buy 10                          # price 10 QNT worth
quant-cli swap DOGE2 buy 10 1                         # buy, max 1% slippage
quant-cli swap DOGE2 sell 20000
quant-cli listtokens 0 50 liquidity
quant-cli sendtoken DOGE2 tqnt1... 123.45
```
External wallets (browser extension, websites) use `getaddresscoins` + `sendrawtransaction`.

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

MIT. Vendored: BLAKE3 (CC0/Apache-2.0), PQClean Falcon (MIT/CC0),
miniupnpc (BSD-3), nlohmann/json (MIT), BIP-39 wordlist (MIT).
