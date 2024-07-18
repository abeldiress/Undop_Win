build-and-run:
  gcc filtered_packets.c -o filtered_packets.exe -I../Include -L../Lib/x64/ -lwpcap -lws2_32 \
	.\filtered_packets.exe