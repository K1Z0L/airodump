#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <iostream>
using namespace std;

#define MAC_SIZE 6

typedef struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__)) IRH;

typedef struct ieee80211_header {
    uint8_t subtype;
    uint8_t flags;
    uint16_t duration_id;
    uint8_t dst_addr[MAC_SIZE];
    uint8_t src_addr[MAC_SIZE];
    uint8_t bss_id[MAC_SIZE];
    uint16_t seq_ctl;
} __attribute__((__packed__)) IH;

typedef struct beacon {
    uint8_t bss_id[MAC_SIZE];
    int beacons;
    int data;
    bool essid_set;
    char ess_id[256];
    int channels;
}BEACON;
