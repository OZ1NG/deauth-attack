#ifndef DEAUTH_H
#define DEAUTH_H
#include <stdint.h>
#include <pcap.h>

class Deauth
{
private:
    struct Ieee80211_radiotap_header {
        uint8_t  it_version;     /* set to 0 */
        uint8_t  it_pad;
        unsigned short it_len;   /* entire length */
        uint32_t it_present;     /* fields present */ // 여러개 있다..
        uint32_t dummy;          // rate... etc....
    };

    /*
    struct Common_dot11_header{
        uint8_t version; // static : 0, 2bit
        uint8_t type;    // frame type, 2bit
        uint8_t subtype; // sub type  , 4bit
        uint8_t flag;    // FCF_FLAG  , 8bit
    };
    */

    struct Deauth_packet{
        struct Ieee80211_radiotap_header radiotap;
        //struct Common_dot11_header common_dot11;
        uint16_t common_dot11;
        uint16_t duration;
        uint8_t  dest_addr[6];
        uint8_t  src_addr[6];
        uint8_t  BSSID[6];
        uint16_t  number;       // sequence number(12bit) + fragment number(4bit)
        uint16_t fixed_param;
    };

    struct Ieee80211_radiotap_header static_radiotap_h = {0, 0, 0xc, 0x00008004, 0x00180002};
    //struct Common_dot11_header common_dot11_h = {0, 0, 12, 0};

    void initialize();

public:
    Deauth();
    struct Deauth_packet deauth_packet;
    void send_packet(pcap_t * pcap, const u_char * packet_data);
};

#endif // DEAUTH_H
