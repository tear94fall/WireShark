

#include "ProtocolHeader.hpp"

namespace Data {
	namespace DataFunction {

		extern int packet_cnt;
		extern int tcp_pkt_cnt;
		extern int udp_pkt_cnt;
		extern int arp_pkt_cnt;
		extern int icmp_pkt_cnt;
		extern bool is_file_save;


		void ClearPacketCnt();

		CString Calculate4HexNumber(CString num1, CString num2, CString num3, CString num4);
		CString Calculate2HexNumber(CString num1, CString num2);

		CString HexToDec(CString _number);
		CString HexToBinary(CString _number);

		CString GetTCPFlagToBin(CString _Flag);
		CString GetTCPFlagToStr(CString _Flag);
		CString GetTCPFlagToLongStr(CString _Flag);

		CString GetIPAddr(Protocol::IP::ip_address ip_addr);
		CString GetFlagSetNotSet(CString _Flag);

		CString MakeIPAddressV6(CString Aclass, CString Bclass, CString Cclass, CString Dclass, CString Eclass, CString Fclass);
		CString ArpOpcde(CString OpcodeNumber);
		CString ArpHardwareType(CString HardwareTypeNumber);
		void FileSave();
		std::string GetCurrentTimeStr();

		BOOL IsNumeric(CString value);
	}
}