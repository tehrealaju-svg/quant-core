# Launching Quant mainnet

Mainnet is compiled in but switched off until the genesis block is fixed. Until then every
program defaults to **testnet**, where you can test everything with coins that are worth nothing.

## Checklist

1. Run testnet for a while: PC node + Pi node + phone wallet, mining, sending, restarting.
2. Pick the launch moment and a genesis message (for example a headline from that day, which
   proves the chain didn't exist before it).
3. Edit `src/consensus/params.cpp`:
   ```cpp
   static constexpr uint64_t MAINNET_GENESIS_TIME = <unix time, e.g. 1795000000>;
   static const char* MAINNET_GENESIS_MESSAGE = "<your message>";
   ```
4. Rebuild and run the tests. The `genesis` test prints the hashes.
5. Optionally flip the default network to mainnet in `src/node/node.h` (`NodeConfig::net`),
   in `quant-cli.cpp`, and in the desktop and Termux clients.
6. Commit, tag `v1.0.0`, push all three repos.
7. Start your node with `quantd -mainnet -createwallet -mine=4`. Block 1 is the first mined
   block; the genesis block itself pays no one (no premine).
8. Keep at least one node reachable (port 7337 forwarded, or a Pi at a friend's place) so new
   nodes can connect in.

Changing anything in `consensus/` after launch is a fork. Do it only with a planned activation
height.
