#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> // Include for Ethernet header definitions

// DNS header structure
struct dnshdr {
    uint16_t id;       // identification number
    uint8_t rd :1;     // recursion desired
    uint8_t tc :1;     // truncated message
    uint8_t aa :1;     // authoritive answer
    uint8_t opcode :4; // purpose of message
    uint8_t qr :1;     // query/response flag
    uint8_t rcode :4;  // response code
    uint8_t cd :1;     // checking disabled
    uint8_t ad :1;     // authenticated data
    uint8_t z :1;      // its z! reserved
    uint8_t ra :1;     // recursion available
    uint16_t q_count;  // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};

void parse_dns_query(const u_char* buffer, int size) {
    const dnshdr* dnsHeader = (const dnshdr*)buffer;
    int dnsHeaderSize = sizeof(dnshdr);
    if (ntohs(dnsHeader->q_count) > 0) { // Check if there are DNS questions
        const char* queryName = (const char*)(buffer + dnsHeaderSize);
        std::cout << "DNS Query: ";
        while (*queryName) {
            if (isprint((unsigned char)*queryName)) {
                std::cout << *queryName;
            } else {
                std::cout << '.';
            }
            ++queryName;
        }
        std::cout << std::endl;
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* ethernetHeader = (struct ether_header*)packet;
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    const struct udphdr* udpHeader;
    if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (struct udphdr*)((u_char*)ipHeader + (ipHeader->ip_hl * 4));
        if (ntohs(udpHeader->uh_dport) == 53) { // DNS typically uses port 53
            const u_char* dnsData = (const u_char*)udpHeader + sizeof(struct udphdr);
            parse_dns_query(dnsData, pkthdr->caplen - ((const u_char*)udpHeader - packet) - sizeof(struct udphdr));
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf); // Ensure "en0" is your active network interface, or find dynamically
    if (handle == nullptr) {
        std::cerr << "Failed to open device: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(handle, -1, packetHandler, nullptr) < 0) {
        std::cerr << "Error occurred during pcap loop: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}


// #include <iostream>
// #include <pcap.h>
// #include <netinet/in.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <arpa/inet.h>
// #include <netinet/if_ether.h>

// void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
//     const struct ether_header* ethernetHeader = (struct ether_header*)packet;
//     const struct ip* ipHeader;
//     const struct tcphdr* tcpHeader;

//     if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
//         ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
//         char srcIp[INET_ADDRSTRLEN];
//         char dstIp[INET_ADDRSTRLEN];
//         inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
//         inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

//         std::cout << "IP Src: " << srcIp << ", IP Dst: " << dstIp << std::endl;
//         std::cout << "IP Header Length: " << (unsigned int)ipHeader->ip_hl << std::endl;
//         std::cout << "Type of Service: " << (unsigned int)ipHeader->ip_tos << std::endl;
//         std::cout << "Total Length: " << ntohs(ipHeader->ip_len) << std::endl;
//         std::cout << "Identification: " << ntohs(ipHeader->ip_id) << std::endl;

//         if (ipHeader->ip_p == IPPROTO_TCP) {
//             tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
//             std::cout << "TCP Src Port: " << ntohs(tcpHeader->th_sport) << ", TCP Dst Port: " << ntohs(tcpHeader->th_dport) << std::endl;
//             std::cout << "Sequence Number: " << ntohl(tcpHeader->th_seq) << std::endl;
//             std::cout << "Acknowledgment Number: " << ntohl(tcpHeader->th_ack) << std::endl;
//             std::cout << "TCP Header Length: " << (unsigned int)(tcpHeader->th_off) << std::endl;
//             std::cout << "Flags: " << (unsigned int)tcpHeader->th_flags << std::endl;
//             std::cout << "Window Size: " << ntohs(tcpHeader->th_win) << std::endl;
//         }
//     }
//     std::cout << std::endl;
// }

// int main() {
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_if_t *alldevs;
//     pcap_if_t *device;
//     if (pcap_findalldevs(&alldevs, errbuf) == -1) {
//         std::cerr << "Error finding devices: " << errbuf << std::endl;
//         return 1;
//     }

//     // Use the first device
//     device = alldevs;
//     std::cout << "Capturing packets on device: " << device->name << std::endl;

//     pcap_t *descr = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
//     if (descr == nullptr) {
//         std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
//         return 1;
//     }

//     // Loop indefinitely (-1 means infinite loop)
//     if (pcap_loop(descr, -1, packetHandler, nullptr) < 0) {
//         std::cerr << "pcap_loop() failed: " << pcap_geterr(descr) << std::endl;
//         pcap_close(descr);
//         return 1;
//     }

//     pcap_close(descr);
//     pcap_freealldevs(alldevs);  // Free the device list
//     return 0;
// }
