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

		int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }


        printf("[%d] %u bytes captured\n",index, header->caplen);
        //ethernet hdr
        eth_hdr = (libnet_ethernet_hdr*)packet;

        //ethernet hdr source_mac
        printf("sour MAC : ");
        for (int i = 0; i<ETHER_ADDR_LEN; i++){
            if (i == ETHER_ADDR_LEN-1){
                printf("0x%02x", eth_hdr->ether_shost[i]);
            }
            else{
                printf("0x%02x:", eth_hdr->ether_shost[i]);
            }
        }
        printf("\n");
        printf("dest MAC : ");
        //ethernet hdr dest_mac
        for (int i = 0; i<ETHER_ADDR_LEN; i++){
            if (i == ETHER_ADDR_LEN-1){
                printf("0x%02x", eth_hdr->ether_shost[i]);
            }
            else{
                printf("0x%02x:", eth_hdr->ether_dhost[i]);
            }
        }
        printf("\n");
        packet += 14;
        if (eth_hdr->ether_type == 0x0008){
            libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)packet;

            //IP hdr source_ip
            printf("sour IP : ");
            printf("%s\n", inet_ntoa(ip_hdr_v4->ip_src));

            //IP hdr destination_ip
            printf("dest IP : ");
            printf("%s", inet_ntoa(ip_hdr_v4->ip_dst));

            if (ip_hdr_v4->ip_p == 6){
                packet += (ip_hdr_v4->ip_hl*4);
                tcp_hdr = (libnet_tcp_hdr *)packet;

                //TCP hdr
                printf("\nsour port : %d\n", ntohs(tcp_hdr->th_sport));
                printf("dest port : %d", ntohs(tcp_hdr->th_dport));

            }
            else{
                printf("This is not TCP / protocol : %d", ip_hdr_v4->ip_p);
                //printing end..
                index++;
                printf("\n");
                continue;
            }
        }else {
            printf("This is not IPv4");
            //printing end..
            index++;
            printf("\n");
            continue;
        }
        //printing end..
        index++;
        printf("\n");

	}

	pcap_close(pcap);
}
