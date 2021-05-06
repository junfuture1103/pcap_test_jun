#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

struct Param {
	char* dev_{nullptr};

	bool parse(int argc, char* argv[]) {
		if (argc != 2) {
			usage();
			return false;
		}
		dev_ = argv[1];
		return true;
	}

	static void usage() {
		printf("syntax: pcap-test <interface>\n");
		printf("sample: pcap-test wlan0\n");
	}
};


int main(int argc, char* argv[]) {
    int index = 1;
	Param param;
	if (!param.parse(argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
        libnet_ethernet_hdr *eth_hdr;
        libnet_tcp_hdr *tcp_hdr;

        const u_char* packet;
        int data_size;

		int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }
        //hdr
        eth_hdr = (libnet_ethernet_hdr*)packet;
        libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(packet + sizeof(libnet_ethernet_hdr));

        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
            //printf("PASS! type : %d\n", ntohs(eth_hdr->ether_type));
            continue;
        }
        if(ip_hdr_v4->ip_p != IPPROTO_TCP){
            //printf("PASS! protocol : %d\n", ip_hdr_v4->ip_p);
            continue;
        }

        printf("[%d] %u bytes captured\n",index, header->caplen);

        //ethernet hdr source_mac
        printf("\nsour MAC : ");
        for (int i = 0; i<ETHER_ADDR_LEN; i++){
            if (i == ETHER_ADDR_LEN-1){
                printf("0x%02x", eth_hdr->ether_shost[i]);
            }
            else{
                printf("0x%02x:", eth_hdr->ether_shost[i]);
            }
        }

        //ethernet hdr dest_mac
        printf("\n");
        printf("dest MAC : ");
        for (int i = 0; i<ETHER_ADDR_LEN; i++){
            if (i == ETHER_ADDR_LEN-1){
                printf("0x%02x", eth_hdr->ether_shost[i]);
            }
            else{
                printf("0x%02x:", eth_hdr->ether_dhost[i]);
            }
        }
        printf("\n");

        //IP hdr source_ip
        printf("sour IP : ");
        printf("%s\n", inet_ntoa(ip_hdr_v4->ip_src));

        //IP hdr destination_ip
        printf("dest IP : ");
        printf("%s", inet_ntoa(ip_hdr_v4->ip_dst));

        packet = packet + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4);
        tcp_hdr = (libnet_tcp_hdr *)packet;

        //TCP hdr
        printf("\nsour port : %d\n", ntohs(tcp_hdr->th_sport));
        printf("dest port : %d", ntohs(tcp_hdr->th_dport));

        //DATA
        printf("\nip_hdr_v4 : %d\n",ntohs(ip_hdr_v4->ip_len));
        data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;
        printf("\nDATA size : %d", data_size);

        if (data_size != 0){
            if (data_size > 16){
                data_size = 16;
            }
            packet += tcp_hdr->th_off*4;
            printf("\nDATA : ");
            for (int i = 0; i<data_size; i++){
                printf("%0x02x ", *(packet+i));
            }
        }else{
            printf("\nData size is 0\n");
        }
        //printing end..
        index++;
        printf("\n");

	}

	pcap_close(pcap);
}
