# Android root TUN auto-route → rtnetlink

## Changes
1. **Cargo.toml** — enable `rtnetlink 0.16` + `netlink-packet-route 0.21` for
   `linux` **and** `android`. These versions hardcode `AddressFamily::Bridge`
   (value 7) so they compile against bionic (no `AF_BRIDGE`).

2. **src/tun/route.rs** — Android root auto-route uses the same rtnetlink path
   as Linux instead of shelling out to `ip rule` / `ip route`.
   - Shared `NetlinkInstalled` + Drop cleanup
   - Linux keeps classic mihomo topology (`add_rules_classic_mihomo`)
   - Android uses netd-aware topology (`add_rules_android_netlink`):
     fwmark → phys table, iif tun → main, excludes → phys, catch-all → TUN table
   - Default rule priority still 8000 on Android (netd owns 9000–18000)

3. **src/tun/device.rs** — comment only (root path still creates `/dev/tun`).

## Notes
- VpnService external-FD mode is unchanged (no auto-route from this binary).
- Root mode still requires a non-zero fwmark for loop prevention.
- Apply by copying files into your tree (or diff against original).
