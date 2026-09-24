# Quant: A Post-Quantum Peer-to-Peer Electronic Cash System

*Design notes, section by section against Bitcoin's whitepaper (Nakamoto, 2008).*

## Abstract

Quant keeps what made Bitcoin work: proof-of-work, a UTXO ledger, longest (most-work) chain,
no trusted parties. It changes three things that decide whether a coin survives for a century:

1. **Signatures that survive quantum computers.** Bitcoin's ECDSA/Schnorr keys fall to Shor's
   algorithm. Quant uses **Falcon-512** (NIST FN-DSA) and commits a **SPHINCS+** hash-based
   backup key inside every address.
2. **A chain that stays small** even though post-quantum signatures are ~20x bigger than
   Schnorr: signatures are segregated and **pruned once buried a week deep**, and one signature
   covers every input from the same address.
3. **Anyone can join with nothing but the software.** No DNS seeds, no project servers: nodes
   find each other through the public **BitTorrent DHT**, LAN broadcast, and saved peers.

| | Bitcoin | Quant |
|---|---|---|
| Signature | ECDSA / Schnorr (secp256k1) | Falcon-512 + SPHINCS+ backup |
| Hash / PoW | SHA-256d | BLAKE3 |
| Block time | 10 min | 2 min |
| Difficulty | every 2016 blocks | every block (LWMA, 2 h window) |
| Supply | 21M, 4-year halvings | ~210.24M, 8-year halvings, ends after ~256 years |
| Smallest unit | 10^-8 | 10^-10 |
| Fees | per vbyte, market | per byte, minimum 0.00001 QNT/KB |
| Peer discovery | DNS seeds run by developers | BitTorrent DHT + LAN + saved peers |

## 1. Introduction

Unchanged goal: payments between two parties without a trusted third party. Bitcoin's weak
points over a 100-year horizon are not its economics, they are **its cryptography** (quantum)
and **its bootstrap** (DNS seeds are a handful of domains run by known people).

## 2. Transactions

Bitcoin defines a coin as a chain of signatures. Quant keeps the UTXO model with a simpler,
script-less output: `amount + address`, where

```
address = BLAKE3("Quant v1 address", H(falcon_pubkey) || H(sphincs_pubkey))
```

Spending reveals the Falcon public key (897 B) and a Falcon signature (~655 B). The SPHINCS+
key stays hidden behind its hash. If lattice cryptography is ever broken, a soft fork disables
Falcon spends and owners move coins with their SPHINCS+ key (7.9 KB signatures, relying only on
hash security). A single wallet seed produces both keys, so nobody has to do anything in
advance.

Every output address is a hash, so **public keys are never exposed until coins are spent**.
Wallets use a fresh address for change, so a quantum attacker can't pre-compute keys from
coins sitting at rest.

**Signature sharing:** all inputs of a transaction that spend from the same address are covered
by one signature (`WitnessRef`). A 3-input payment is ~1.8 KB instead of ~4.8 KB.

**Encoding:** canonical varints everywhere, so there is exactly one serialization per object
(no encoding malleability); the txid excludes signatures (no signature malleability).

## 3. Timestamp Server

Same idea: each block commits to the previous block's hash. The 120-byte header carries two
Merkle roots: one over txids (kept forever) and one over signatures (prunable). Merkle trees
carry an odd node up instead of duplicating it, which removes Bitcoin's CVE-2012-2459
ambiguity; inner nodes are domain-separated from leaves.

## 4. Proof-of-Work

BLAKE3 of the 120-byte header. BLAKE3 is fast on phones and Raspberry Pis (NEON), so the chain
is cheap to verify everywhere. BLAKE3 ASICs already exist (they are used for another coin), and
Quant deliberately doesn't fight them: CPUs can mine early on, and dedicated hardware can
secure the chain later.

**Difficulty** is recalculated every block with LWMA (linearly weighted moving average over the
last 60 blocks) instead of every 2016 blocks, so a sudden drop in hashrate can't freeze the
chain for weeks, a real risk for a young coin. Solve times are clamped, headers can be at most
6 minutes in the future, and they must be later than the median of the last 11.

Quantum note: Grover's algorithm only gives a square-root speedup on hashing, which acts like
extra hardware, not a break. 256-bit BLAKE3 keeps 128-bit security against it.

## 5. Network

Bitcoin's steps (broadcast txs, collect into blocks, find PoW, broadcast, accept if valid,
build on it) are unchanged. What changes is **how you find the network in the first place**.

Bitcoin Core ships DNS seeds, a few hostnames run by developers. Quant ships none. A new node:

1. loads peers it saw last time (`peers.txt`), and DHT nodes it knew (`dht.dat`);
2. joins the public **BitTorrent Mainline DHT** (BEP 5), millions of nodes owned by nobody, and
   looks up a 20-byte key derived from the Quant network name + genesis hash; every Quant node
   announces itself under that key;
3. broadcasts on the LAN (so a phone, a PC and a Pi at home find each other instantly);
4. gossips addresses with every peer (`getaddr`/`addr`);
5. accepts manual `addnode` as a last resort.

Nodes listen on IPv4 **and IPv6** and use both the IPv4 and IPv6 DHTs (BEP 32). Many home and mobile connections (Starlink, 4G/5G) put IPv4 behind carrier-grade NAT with no port forwarding, but give every device a public IPv6 address, so those nodes are still reachable over IPv6. Where the router allows it, nodes also forward their IPv4 port with UPnP. The only outside
contacts are the generic DHT bootstrap routers, and only on a node's very first run; after that
it remembers DHT nodes itself.

Sync is headers-first: headers (120 B) are validated for PoW and difficulty before any block
data is downloaded, in parallel from several peers.

## 6. Incentive

Rewards start at 50 QNT per block and halve every 2,102,400 blocks (8 years). There is no
premine, no developer reward, and the genesis block pays no one. Rewards stop once a halving
would drop below 0.0000000125 QNT (125 base units). The last reward is 0.0000000232 QNT, in
year ~256.

| Years | Reward | Supply at end |
|---|---|---|
| 0–8 | 50 | 105.1M |
| 8–16 | 25 | 157.7M |
| 16–24 | 12.5 | 184.0M |
| 24–32 | 6.25 | 197.1M |
| 32–64 | 3.125 → 0.39 | 209.4M |
| 64–256 | 0.195 → 0.0000000232 | 210,239,999.95 |

The fee is a flat per-byte minimum (0.00001 QNT per KB, about 0.00002 QNT for a normal payment)
and doesn't depend on the amount sent. As with Bitcoin, long-term security eventually depends
on fees; the 8-year halvings stretch the subsidy era to decades.

## 7. Reclaiming Disk Space

Bitcoin proposed pruning spent transactions from Merkle trees but in practice stores all
signatures forever (~60% of its chain). With post-quantum signatures that would be
catastrophic, so Quant goes further:

* **Signatures are segregated.** A block is stored as *core* (header + inputs/outputs) plus a
  separate witness file.
* **Witnesses are deleted once a block is 5,040 blocks (~1 week) deep.** Undo data for
  reorganizations is deleted at the same depth; forks deeper than that are refused.
* A new node validates **everything** (amounts, double spends, PoW, Merkle roots) for the
  whole history, and checks signatures for any block whose signatures its peers still have
  (always the last week). Older signatures were checked by every node that was online during
  that week and are buried under a week of proof-of-work. This is the same trust assumption as
  Bitcoin Core's `assumevalid`, made explicit and applied by depth.
* Stored per typical payment: **~116 bytes forever** versus ~1.7 KB transmitted.

A node can run with `-noprune` to keep every signature (archive node).

## 8. Simplified Payment Verification

The Termux wallet does SPV: it downloads headers (120 B each, ~31 MB per year), checks
proof-of-work and difficulty itself, then asks full nodes for its coins. Each coin arrives with
the full transaction and a Merkle proof that ties it to a header the wallet has verified. It
queries several peers and cross-checks them. Transactions are signed on the phone and the keys
never leave it.

## 9. Combining and Splitting Value

Same as Bitcoin: multiple inputs, one payment output plus change. Outputs under 0.000001 QNT
(dust) are invalid at the consensus level, which keeps the UTXO set small.

## 10. Privacy

Same model as Bitcoin: amounts are public, identities are not. Wallets use a new address for
change. Signature sharing links inputs from the same address (already linked in practice).

## 11. Calculations

The attacker catch-up probability from Bitcoin's section 11 applies unchanged per block of
work. Because blocks come 5x faster, wait 5x more blocks for the same security as Bitcoin: 6
Bitcoin confirmations (1 hour) ≈ 30 Quant confirmations (1 hour). For small payments, a few
confirmations are enough.

## 12. Conclusion and honest limitations

* Falcon-512 is newer than ECDSA. The SPHINCS+ backup exists because of that.
* BLAKE3 proof-of-work is ASIC-friendly by design.
* A young, low-hashrate chain is vulnerable to 51% attacks. This is true of every new coin.
* Behind CGNAT (common with mobile and satellite ISPs), a node can connect out but can't accept
  connections. The network needs some reachable nodes (port-forwarded or IPv6).
* This software has not been audited. Treat it as an experiment.
