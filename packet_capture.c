#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

int is_printable(unsigned char c) {
    return (c >= 32 && c <= 126);
}

// HTTP 메시지 여부 확인
int is_http_message(const unsigned char *data, int length) {
    if (length > 3 && (strncmp((const char*)data, "GET", 3) == 0 ||
                       strncmp((const char*)data, "HTTP/", 5) == 0)) {
        return 1; 
    }
    return 0;
}

// HTTP 메시지 출력
void print_http_message(const unsigned char *data, int length) {
    int i;
    int in_header = 1;  
    int last_char_flag = 0; 

    for (i = 0; i < length; i++) {
        if (is_printable(data[i])) {
            if (data[i] == '\r' && i + 1 < length && data[i + 1] == '\n') {
                if (in_header) {
                    printf("\n");
                    in_header = 0;
                }
                i++; 
                if (!last_char_flag) {
                    printf("\n");  
                    last_char_flag = 1;
                }
            } else {
                printf("%c", data[i]);
                last_char_flag = 0; 
            }
        } else {
            if (!last_char_flag) {
                printf("\n");  
                last_char_flag = 1;
            }
        }
    }
    printf("\n");
}

// MAC 주소 출력
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 캡쳐
void got_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;  
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));  
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));  
    
    unsigned char *data = (unsigned char *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));  

    int data_len = pkthdr->len - (sizeof(struct ether_header) + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));  

    // Ethernet Header 출력
    printf("\n================================\n\n");
    printf("Ethernet Header\n");
    printf("Src MAC: ");
    print_mac_address(eth_header->ether_shost);  
    printf("\n");
    printf("Dst MAC: ");
    print_mac_address(eth_header->ether_dhost);  
    printf("\n\n");

    // IP Header 출력
    printf("IP Header\n");
    printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));  
    printf("Dst IP: %s\n\n", inet_ntoa(ip_header->ip_dst));  

    // TCP Header 출력
    printf("TCP Header\n");
    printf("Src Port: %u\n", ntohs(tcp_header->th_sport));  
    printf("Dst Port: %u\n\n", ntohs(tcp_header->th_dport));  

    if (is_http_message(data, data_len)) {
        printf("HTTP Message\n");
        print_http_message(data, data_len);
    }
}


int main() {
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp port 80";  
    char network_interface[100];

    printf("enter the network interface: ");
    scanf("%s", network_interface);


    handle = pcap_open_live(network_interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open interface: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        return 1;
    }

    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
