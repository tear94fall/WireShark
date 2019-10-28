
#include "pch.h"
#include "Data.hpp"

int Data::DataFunction::packet_cnt = 0;
int Data::DataFunction::tcp_pkt_cnt = 0;
int Data::DataFunction::udp_pkt_cnt = 0;
int Data::DataFunction::arp_pkt_cnt = 0;
int Data::DataFunction::icmp_pkt_cnt = 0;

CString Data::DataFunction::Calculate4HexNumber(CString num1, CString num2, CString num3, CString num4) {
	return CString(std::to_string((
		_ttoi(HexToDec(num1)) * 16 * 16 * 16 +
		_ttoi(HexToDec(num2)) * 16 * 16 +
		_ttoi(HexToDec(num3)) * 16 +
		_ttoi(HexToDec(num4)) * 1
		)).c_str());
}

CString Data::DataFunction::Calculate2HexNumber(CString num1, CString num2) {
	return CString(std::to_string((
		_ttoi(HexToDec(num1)) * 16 +
		_ttoi(HexToDec(num2)) * 1
		)).c_str());
}

CString Data::DataFunction::HexToDec(CString _number) {
	wchar_t* end = NULL;
	long value = wcstol(_number, &end, 16);

	CString decStr;
	decStr.Format(L"%d", value);

	return decStr;
}

CString Data::DataFunction::HexToBinary(CString _number) {
	CString result, temp1, temp2, temp3, temp4;

	temp1 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp2 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp3 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	temp4 = CString((std::to_string(_ttoi(_number) / 2)).c_str());

	result = temp4 + temp3 + temp2 + temp1;

	return result;
}



CString Data::DataFunction::GetTCPFlagToBin(CString _Flag) {
	CString Result;
	CString FirstByte = _Flag.Mid(0, 1);
	CString SecondByte = _Flag.Mid(1, 1);
	CString ThirdByte = _Flag.Mid(2, 1);

	FirstByte = Data::DataFunction::HexToDec(FirstByte);
	SecondByte = Data::DataFunction::HexToDec(SecondByte);
	ThirdByte = Data::DataFunction::HexToDec(ThirdByte);

	FirstByte = Data::DataFunction::HexToBinary(FirstByte);
	SecondByte = Data::DataFunction::HexToBinary(SecondByte);
	ThirdByte = Data::DataFunction::HexToBinary(ThirdByte);

	Result = FirstByte + SecondByte + ThirdByte;

	return Result;
}

CString Data::DataFunction::GetTCPFlagToStr(CString _Flag) {
	CString Result = L"";

	CString URG = _Flag.Mid(0, 1).Compare(L"1") == 0 ? L"URG" : L"NULL";
	CString ACK = _Flag.Mid(1, 1).Compare(L"1") == 0 ? L"ACK" : L"NULL";
	CString PSH = _Flag.Mid(2, 1).Compare(L"1") == 0 ? L"PSH" : L"NULL";
	CString RST = _Flag.Mid(3, 1).Compare(L"1") == 0 ? L"RST" : L"NULL";
	CString SYN = _Flag.Mid(4, 1).Compare(L"1") == 0 ? L"SYN" : L"NULL";
	CString FIN = _Flag.Mid(5, 1).Compare(L"1") == 0 ? L"FIN" : L"NULL";

	CString Flags[6] = { URG, ACK,PSH,RST,SYN,FIN };

	for (int i = 0; i < 6; i++) {
		if (Flags[i].Compare(L"NULL") != 0) {
			Result.Append(Flags[i]);
			Result.Append(L", ");
		}
	}

	Result = Result.Mid(0, Result.GetLength() - 2);

	return Result;
}


CString Data::DataFunction::GetTCPFlagToLongStr(CString _Flag) {
	CString Result = L"";
	CString FlagArray[6] = { L"U",L"A",L"P",L"R",L"S",L"F" };

	for (int i = 0; i < _Flag.GetLength(); i++) {
		if (_Flag.Mid(i, 1) == L"1" && i > 5) {
			Result.Append(FlagArray[i - 6]);
		} else {
			Result.Append(L". ");
		}
	}

	return Result;
}


CString Data::DataFunction::GetIPAddr(Protocol::IP::ip_address ip_addr) {
	CString temp_ip_addr;
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte1)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte2)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte3)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte4)).c_str());

	return temp_ip_addr;
}


CString Data::DataFunction::MakeIPAddressV6(CString Aclass, CString Bclass, CString Cclass, CString Dclass, CString Eclass, CString Fclass) {
	return Aclass + L":" + Bclass + L":" + Cclass + L":" + Dclass + L":" + Eclass + L":" + Fclass;
}

CString Data::DataFunction::ArpOpcde(CString OpcodeNumber) {
	CString OpcodeStr = L"";
	if (OpcodeNumber.Compare(L"1") == 0) {
		OpcodeStr = "Request";
	} else if (OpcodeNumber.Compare(L"2") == 0) {
		OpcodeStr = "Reply";
	}
	return OpcodeStr;
}

CString Data::DataFunction::ArpHardwareType(CString HardwareTypeNumber) {
	CString HardwareTypeStr = L"";
	if (HardwareTypeNumber.Compare(L"1") == 0) {
		HardwareTypeStr = "Ethernet";
	} else if (HardwareTypeNumber.Compare(L"2") == 0) {
		HardwareTypeStr = "Experimental Ethernet";
	} else if (HardwareTypeNumber.Compare(L"3") == 0) {
		HardwareTypeStr = "Amateur Radio";
	} else if (HardwareTypeNumber.Compare(L"4") == 0) {
		HardwareTypeStr = "Proteon ProNet Token Ring";
	} else if (HardwareTypeNumber.Compare(L"5") == 0) {
		HardwareTypeStr = "IEEE 802.3 networks";
	}

	return HardwareTypeStr;
}


CString Data::DataFunction::GetFlagSetNotSet(CString _Flag) {
	int Length = _Flag.GetLength();

	if (Length == 3) {
		return (_Flag.Compare(L"000") == 0) ? L"Not set" : L"Set";
	}
	if (Length == 1) {
		return (_Flag.Compare(L"0") == 0) ? L"Not set" : L"Set";
	}
	return L"";
}

std::string Data::DataFunction::GetCurrentTimeStr() {
	time_t     tm_time;
	struct tm* st_time;
	char       buff[1024];

	time(&tm_time);
	st_time = localtime(&tm_time);
	strftime(buff, 1024, "%Y-%m-%d %p %H:%M:%S", st_time);

	std::string temp_buf = buff;

	return temp_buf;
}

void Data::DataFunction::ClearPacketCnt() {
	packet_cnt = 0;
	tcp_pkt_cnt = 0;
	udp_pkt_cnt = 0;
	arp_pkt_cnt = 0;
	icmp_pkt_cnt = 0;
}

BOOL Data::DataFunction::IsNumeric(CString value) {
	const int length_of_str = value.GetLength();
	if (length_of_str == 0) {
		return FALSE;
	} else {
		for (int i = 0; i < length_of_str; i++) {
			if (!isdigit(value.Mid(i, 1).GetAt(0))) {
				return FALSE;
			}
		}
		return TRUE;
	}
}

