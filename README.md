
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

This implementation uses packet sniffing, which can be buggy at times depending on your browser. Might consider switching to using ```windows.h``` to view traffic.


TODO: Fix DNS caching issue
TODO: add pre-select device option