#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

BOOL LoadNpcapDlls() {
  _TCHAR npcap_dir[512];
  UINT len;
  len = GetSystemDirectory(npcap_dir, 480);
  if (!len) {
    fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
    return FALSE;
  }
  _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
  if (SetDllDirectory(npcap_dir) == 0) {
    fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
    return FALSE;
  }
  return TRUE;
}

/* 4 bytes IP address */
typedef struct ip_address {
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header {
  u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
  u_char  tos;     // Type of service 
  u_short tlen;    // Total length 
  u_short identification; // Identification
  u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;      // Time to live
  u_char  proto;    // Protocol
  u_short crc;      // Header checksum
  ip_address  saddr; // Source address
  ip_address  daddr; // Destination address
  u_int  op_pad;     // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
  u_short sport; // Source port
  u_short dport; // Destination port
  u_short len;   // Datagram length
  u_short crc;   // Checksum
}udp_header;

// using pcap type definition to keep it in spirit...
typedef struct packet_data {
  u_char *link_layer;

} packet_data;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

const int HOSTNAME_OFFSET = 54;
const char *bad_sites_filename = "bad_sites.txt";
#define PACKET_MAX_LEN 65536
#define BAD_SITES_MAX_LEN 1000

char *bad_sites[BAD_SITES_MAX_LEN];

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int intf = 0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_int netmask;
  char packet_filter[] = "udp port 53";
  struct bpf_program fcode;

  /* Load Npcap and its functions. */
  if (!LoadNpcapDlls()) {
    fprintf(stderr, "Couldn't load Npcap\n");
    return 1;
  }

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
     NULL, &alldevs, errbuf) == -1) {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    return 1;
  }
  
  for(d=alldevs; d; d=d->next) {
    printf("%d. %s", ++intf, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if(intf == 0) {
    printf("\nNo interfaces found! Make sure Npcap is installed.\n");
    return -1;
  }
  
  printf("Enter the interface number (1-%d): ", intf);
  scanf_s("%d", &inum);

  while (inum < 1 || inum > intf) {
    printf("\nInterface number out of range.");
    printf("Enter the interface number (1-%d): ", intf);
    scanf_s("%d", &inum);
  }

  for(d = alldevs, intf = 0; intf < inum-1; d = d->next, intf++);
  
  if ((adhandle = pcap_open(d->name, PACKET_MAX_LEN, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,errbuf)) == NULL) {
    fprintf(stderr,
      "\nUnable to open the adapter. %s is not supported by Npcap\n",
      d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }
  
  if(pcap_datalink(adhandle) != DLT_EN10MB) {
    fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  /*-------------------------------------------*/

  // some masking thing from npcap SDK

  /* Retrieve the mask of the first address of the interface */
  if(d->addresses != NULL)
    netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
  else
    /* If the interface is without addresses
     * we suppose to be in a C class network */
    netmask=0xffffff; 
  
  /*-------------------------------------------*/


  if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
    fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }
  
  if (pcap_setfilter(adhandle, &fcode) < 0) {
    fprintf(stderr,"\nError setting the filter.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }
  
  printf("\nlistening on %s...\n", d->description);

  FILE *bad_sites_file = fopen(bad_sites_filename, "r");
  if (bad_sites_file == NULL) {
    fprintf(stderr, "Error opening file");
    return -1;
  }

  int i;
  for (i = 0; i < BAD_SITES_MAX_LEN - 1; ++i) {
    bad_sites[i] = malloc(256 * sizeof(char));
    if (fgets(bad_sites[i], 256, bad_sites_file) == NULL) {
      free(bad_sites[i]);
      break;
    }
  }

  printf("bad_sites.txt processed...\n");
  
  pcap_freealldevs(alldevs);  
  pcap_loop(adhandle, 0, packet_handler, NULL);
  
  for (int j = 0; j < i; ++j) free(bad_sites[j]);
  return 0;
}

void parse_hostname(char *hostname, const u_char *pkt_data) {
  const u_char *src = pkt_data + HOSTNAME_OFFSET;
  
  int i = 0;
  for (; i < PACKET_MAX_LEN - 1 && src[i] != '\0'; i++) {
    hostname[i] = src[i];
  }
  hostname[i] = '\0';
}

int change_brightness(int brightness) {
  char brightness_str[4];
  char command[200];
  sprintf(brightness_str, "%d", brightness);
  // ik this line is some bs im just prototyping
  snprintf(command, sizeof(command), "powershell.exe $myMonitor = Get-WmiObject -Namespace root\\wmi -Class WmiMonitorBrightnessMethods; $myMonitor.wmisetbrightness(3, %s)", brightness_str);
  return system(command);
}

int trigger_brightness_process() {
  char current_brightness[40];

  FILE *cmdstream = popen("powershell.exe $myMonitor = Get-WmiObject -Namespace root\\wmi -Class WmiMonitorBrightness; echo $myMonitor.CurrentBrightness", "-r");

  if (!cmdstream || fread(current_brightness, sizeof(char), 3, cmdstream) < 1)  {
    perror("Failed getting current brightness");
    return -1;
  } else {
    pclose(cmdstream);
  }

  current_brightness[sizeof(current_brightness) - 1] = '\0';

  if (change_brightness(10) != 0) {
    return -1;
  }

  for (int i = 20; i <= atoi(current_brightness); i += 10) {
    if (change_brightness(i) != 0) {
      return -1;
    }
  }
  
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  // printf("Packet length: %d\n", header->len);

  // for (int i = 0; i < header->len; i++) {
  //   printf("%02x ", pkt_data[i]);
  //   if ((i + 1) % 16 == 0)
  //     printf("\n");
  // }

  char hostname[PACKET_MAX_LEN];

  parse_hostname(hostname, pkt_data);

  printf("Hostname %s\n", hostname);

  for (int i = 0; i < BAD_SITES_MAX_LEN; ++i) {
    if (strstr(hostname, bad_sites[i]) != NULL) {
      printf("MATCH FOUND: %x\n", bad_sites[i]);
      if (trigger_brightness_process() != 0) {
        printf("Error changing brightness.\n");
        exit(1);
      }
      break;
    }
  }
}