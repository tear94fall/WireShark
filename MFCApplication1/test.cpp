
#include "pcap.h";
#include <string>

typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} upd_packet_header;


namespace packet_sniff {
	namespace config {
		class PacketSniff {
		public:
			pcap_if_t* all_network_interfaces, * target_network_interface;
			pcap_t* fp;
			struct pcap_pkthdr* packer_header;
			u_char errbuf[PCAP_ERRBUF_SIZE];

		public:
			int find_all_network_interface(void) {
				if (-1 == !pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &all_network_interfaces, (char*)errbuf)) {
					return -1;
				}else {
					return 1;
				}
			}
		};
	}
}


namespace Protocol {
	namespace Packet {
		class Packet{
		public:
			std::string protocol_name;
		};

		class TCP :public Protocol::Packet::Packet{
		public:
			TCP(){
				this->protocol_name = "TCP";
			}
		};


		class UDP :public Protocol::Packet::Packet {
		public:
			upd_packet_header upd_header;
			int source_port_number;
			int destination_port_number;
			// checksum
			int udp_packet_length;

		public:
			UDP() {
				this->source_port_number = this->upd_header.source_port;
				this->destination_port_number = this->upd_header.dest_port;


				this->protocol_name = "UDP";
			}
		};


		class ARP :public Protocol::Packet::Packet {
		public:
			int source_port_number;
			int destination_port_nubmer;

		public:
			ARP() {
				this->protocol_name = "ARP";
			}
		};

		class ICMP :public Protocol::Packet::Packet {
		public:
			int source_port_nubmer;
			int destination_port_number;

			ICMP() {
				this->protocol_name = "ICMP";
			}
		};
	}

	namespace PacketHandler {
		class PacketHandler {
		public:
			Protocol::Packet::Packet* target_packet = (Protocol::Packet::Packet*)malloc(sizeof(Protocol::Packet::Packet));
			Protocol::Packet::TCP* tcp;

			void printTargetPacket() {
				printf("%s\n", this->target_packet->protocol_name);
				this->target_packet = tcp;
			}
		};
	}
}