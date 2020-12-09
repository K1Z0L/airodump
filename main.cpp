#include "main.h"

IRH *rhdr;
IH *hdr;
int cnt = 0;
vector<BEACON> v;

void usage(void){
    puts("syntax : airodump <interface>");
    puts("sample : airodump wlan1");
}

void print_mac(uint8_t *mac_addr){
    for(int i=0;i<MAC_SIZE-1;i++){
        printf("%02X:", mac_addr[i]);
    }
    printf("%02X", mac_addr[MAC_SIZE-1]);
}

void print_state(void){
    printf("\033[H\033[J\n");
    puts(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID");
    puts("");
    for(auto tmp: v){
        printf(" ");
        print_mac(tmp.bss_id);
        printf("           %03d                ", tmp.beacons);
        if(tmp.channels){
            printf("%2d", tmp.channels);
        }
        else{
            printf("  ");
        }
        printf("                        ");
        if(tmp.essid_set){
            printf("%s", tmp.ess_id);
        }
        printf("\n");
    }
}

void analyze(const u_char* packet, int length){
    rhdr = (IRH*)packet;
    hdr = (IH*)(packet+rhdr->it_len);
    uint8_t* lan_data = (uint8_t*)(packet+rhdr->it_len+sizeof(IH)+12);

    if(hdr->subtype == 0x80){
        int check = 1;
        for(int i=0; i<v.size();i++){
            if(!memcmp(v[i].bss_id, hdr->bss_id, MAC_SIZE)){
                check = 0;
                v[i].beacons++;
                int idx = rhdr->it_len+sizeof(IH)+12;
                while(idx < length){
                    uint8_t num = packet[idx++];
                    int len = packet[idx++];
                    if(idx + len >= length) break;
                    if(num == 0){
                        v[i].essid_set = true;
                        memcpy(v[i].ess_id, packet+idx, len);
                    }
                    else if(num == 3){
                        v[i].channels = packet[idx];
                    }
                    idx += len;
                }
            }
        }
        if(check){
            BEACON now;
            memcpy(now.bss_id, hdr->bss_id, MAC_SIZE);
            now.beacons = 1;
            now.data = 0;
            now.channels = 0;
                int idx = rhdr->it_len+sizeof(IH)+12;
                while(idx < length){
                    uint8_t num = packet[idx++];
                    int len = packet[idx++];
                    if(idx + len >= length) break;
                    if(num == 0){
                        now.essid_set = true;
                        memcpy(now.ess_id, packet+idx, len);
                    }
                    else if(num == 3){
                        now.channels = packet[idx];
                    }
                    idx += len;
                }
            v.push_back(now);
        }
    }
    print_state();
}

int main(int argc, char* argv[]){
    if(argc != 2){
        usage();
        return 0;
    }

    char* dev = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device(%s)(%s)\n", dev, err_buf);
        return 0;
    }


    while(1){
        print_state();
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0){
            continue;
        };
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        }
        int length = header->caplen;
        cnt++;
        analyze(packet, length);
    }
}
