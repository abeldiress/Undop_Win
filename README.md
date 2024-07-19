# Undop Win

An implementation of Patrick Collison's Undop for Windows. 

The motivation to make this is pretty much the same (despite the web being a bit different since then), so I'll refer to Collison's [original blog post on Undop](https://web.archive.org/web/20090819032605/http://collison.ie/blog/2009/08/undop).

Requires installing [Npcap](https://npcap.com/#download).

To run, add your sites in lowercase to ```bad_sites.txt``` and run in bash:

```bash
make build
.\undop.exe
```

When run, select the proper network adapter that handles WiFi.

For example, with these devices you would select #4:

```
1. rpcap://\Device\NPF_{B083E5E9-90FD-49E2-B864-D2B9C55B0D1A} (Network adapter 'WAN Miniport (Network Monitor)' on local host)
2. rpcap://\Device\NPF_{0BE928C2-E79F-46DF-AA39-F62A523F0375} (Network adapter 'WAN Miniport (IPv6)' on local host)
3. rpcap://\Device\NPF_{C01C9D25-3754-4C1C-9857-032B75A865B1} (Network adapter 'WAN Miniport (IP)' on local host)
4. rpcap://\Device\NPF_{2480A3C1-5B84-4F7E-9DE3-19E1A1745F28} (Network adapter 'Intel(R) Wi-Fi 6 AX201 160MHz' on local host)
5. rpcap://\Device\NPF_{27E83C26-9025-42CF-B6A6-6D0A2C965E73} (Network adapter 'Microsoft Wi-Fi Direct Virtual Adapter #2' on local host)
6. rpcap://\Device\NPF_{DC7163A3-6243-4253-8F02-1B63506F8A4F} (Network adapter 'Microsoft Wi-Fi Direct Virtual Adapter' on local host)
7. rpcap://\Device\NPF_Loopback (Network adapter 'Adapter for loopback traffic capture' on local host)
8. rpcap://\Device\NPF_{5919C7A6-EE3B-4B6E-B900-C4142FD9AFBA} (Network adapter 'TAP-ProtonVPN Windows Adapter V9' on local host)
Enter the interface number (1-8):
```

This implementation uses packet sniffing. Specifically, it checks PORT 53 for DNS lookups, with the idea being that you usage when your machine looks up the IP for any of the bad sites. This can be buggy at times depending on your browser. Might consider switching to using ```windows.h``` to view traffic.

TODO: fix DNS caching issue
TODO: add pre-select device option