---
title: Relays
description: The public WebVPN relays, where they are, their addresses, who runs them, and the fair use limits a person meets.
---

## The public relays

| Relay | Address | Location | Region |
| --- | --- | --- | --- |
| `cz-prg-001.fkn.app` | `79.127.204.69` | Prague, Czech Republic | `eu` |
| `hk-hkg-001.fkn.app` | `152.233.49.59` | Hong Kong | `asia` |

The relay's id is the first part of its name, such as `cz-prg-001`. Each relay takes WebTransport on UDP port 443 and the WebSocket on TCP port 8443, and connects out from the address above. The relay names resolve to IPv4 addresses only.

The live list, with each relay's health and load, is the directory at [fkn.app/v1/relays](https://fkn.app/v1/relays). Each relay also answers `https://<name>:8443/load` with its session count, its session ceiling and its version.

## Choosing a relay

The client picks one by round trip time and load, as [how it works](/docs/how-it-works/#how-a-relay-is-chosen) describes, and an app can [ask for one](/docs/using/#choosing-a-relay) for each socket. On fkn.app, a person can pick one under **Server** in the FKN bar or **Relay server** on the Usage page. **Auto** is the default.

## Who runs them

The public relays are run by Horion Corporation as part of [FKN](https://fkn.app). FKN's [terms](https://fkn.app/terms) and [privacy policy](https://fkn.app/privacy) apply to them, and [what the relay keeps](/docs/what-the-relay-keeps/) sums up what they keep.

## Fair use limits

| Limit | No account | Free account | Premium |
| --- | --- | --- | --- |
| Speed | 10 MiB/s | 10 MiB/s | Up to 1 GiB/s |
| Data each day | 5 GB per internet address | 5 GB per account | No daily cap |
| After the day's data | 1 MiB/s | 1 MiB/s | Not slowed |

- **The speed** is counted on each relay, in both directions, and shared by every socket on that relay. An app connected to both relays gets the speed on each. 10 MiB/s is about 84 megabits per second.
- **The day** starts at 00:00 UTC. Nothing stops when the data is used: transfers slow down until the next day starts.
- **Without an account**, everyone on one IPv4 address, or one IPv6 /64, shares the speed and the day's data. Signed in to FKN, a person has their own in every app they connect to their account.
- **The day's data** is counted across every relay together, and counts traffic through FKN's HTTP proxy too.
- **Premium** costs 5 euros per month. See [plans](https://docs.fkn.dev/user/plans/) and the [terms](https://fkn.app/terms).
