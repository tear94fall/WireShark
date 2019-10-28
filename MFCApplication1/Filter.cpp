
#include "pch.h"
#include "Filter.hpp"

CString Filter::FilterFunction::Filter = L"";
CString Filter::FilterFunction::SuccessFilter = L"";
bool  Filter::FilterFunction::IsFilterApply = false;
CString Filter::FilterFunction::DefaultFilterValue = L"Enter Filter....";


BOOL Filter::FilterFunction::CheckFilter(CString pFilter, std::vector<CString> vec) {
	// Filter는 입력된 필터 값
	// vec은 캡쳐된 패킷의 정보
	BOOL result = FALSE;

	pFilter = pFilter.TrimLeft();
	pFilter = pFilter.TrimRight();

	if (pFilter == L"" || pFilter == DefaultFilterValue) {
		result = TRUE;
		return result;
	}
	CString SIP = vec[1];
	CString DIP = vec[2];
	CString PROTOCOL = vec[3];
	CString LENGTH = vec[4];
	CString PKT_DUMP = vec[6];

	SIP.Replace(L" ", L"");
	DIP.Replace(L" ", L"");
	PKT_DUMP.Replace(L" ", L"");
	PROTOCOL.Replace(L" ", L"");

	CString SPORT = Data::DataFunction::Calculate4HexNumber(PKT_DUMP.Mid(68, 1), PKT_DUMP.Mid(69, 1), PKT_DUMP.Mid(70, 1), PKT_DUMP.Mid(71, 1));
	CString DPORT = Data::DataFunction::Calculate4HexNumber(PKT_DUMP.Mid(72, 1), PKT_DUMP.Mid(73, 1), PKT_DUMP.Mid(74, 1), PKT_DUMP.Mid(75, 1));

	pFilter = pFilter.MakeUpper();
	// Length == 3
	// Length >= 3
	// Length <= 3
	// Length > 3
	// Length < 3

	if (pFilter.Mid(0, 6) == L"LENGTH") {
		CString Operate = pFilter.Mid(6, 3);
		Operate.TrimLeft();
		Operate.TrimRight();

		CString VALUE = pFilter.Mid(9, pFilter.GetLength() - 9);
		VALUE.TrimLeft();
		VALUE.TrimRight();

		int value = _ttoi(VALUE);
		int length = _ttoi(LENGTH);

		if (Operate == L"==") {
			if (length == value) {
				result = TRUE;
			}
		} else if (Operate == L">=") {
			if (length >= value) {
				result = TRUE;
			}
		} else if (Operate == L"<=") {
			if (length <= value) {
				result = TRUE;
			}
		} else if (Operate == L">") {
			if (length > value) {
				result = TRUE;
			}
		} else if (Operate == "<") {
			if (length < value) {
				result = TRUE;
			}
		}

		if (result) {
			return result;
		}
	}


	int FilterLength = pFilter.GetLength();

	if (FilterLength == 3 || FilterLength == 4) {
		if (pFilter == PROTOCOL) {
			result = TRUE;
		} else {
			result = FALSE;
		}

		return result;
	}

	CString SplitOPor = L"OR";
	CString SplitOPand = L"AND";
	int op_cnt = GetCountStr(pFilter, SplitOPor);

	std::vector<int> index_vec;

	index_vec = GetCountStrIdx(pFilter, SplitOPor);

	std::vector<CString> split_vec;
	split_vec = SplitStr(pFilter, SplitOPor);

	std::vector<CString>::iterator split_iter;

	for (split_iter = split_vec.begin(); split_iter != split_vec.end(); split_iter++) {
		if (*split_iter == PROTOCOL) {
			result = TRUE;
			return result;
		}
	}

	/*
	포트번호로 시작
	port == 1    -   9
	port == 65536    -  13
	port ==  1 or ip == 0.0.0.0   - 26
	port == 65536 and ip == 123.123.123.123  - 39

	아이피로 시작
	ip == 0.0.0.0    - 13
	ip == 123.123.123.123  - 21
	ip == 0.0.0.0 or port == 1   - 26
	ip == 123.123.123.123 and port == 65536  - 39
	*/

	std::vector<CString> FilterSingleVec;
	std::vector<CString> FilterOrVec;
	std::vector<CString> FilterAndVec;
	std::vector<CString> FilterOrAndVec;
	std::vector<CString> FilterAndAndVec;

	CString SplitIP = pFilter.Mid(0, 6);
	CString SplitPort = pFilter.Mid(0, 8);
	CString SplitBracket = pFilter.Mid(0, 1);
	CString SplitProtocol;

	int OrIndex = pFilter.Find(L" OR ");
	int AndIndex = pFilter.Find(L" AND ");

	if (SplitIP == L"IP == ") {
		if (FilterLength >= 13 && FilterLength <= 21) {
			SplitIP = pFilter.Mid(6, FilterLength - 6);
			FilterSingleVec.push_back(SplitIP);
		} else if (FilterLength >= 26 && FilterLength <= 39) {
			if (OrIndex != -1 && AndIndex == -1) {
				SplitIP = pFilter.Mid(0, OrIndex);
				SplitPort = pFilter.Mid(OrIndex + 4, FilterLength - OrIndex - 4);

				SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
				SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
				FilterOrVec.push_back(SplitIP);
				FilterOrVec.push_back(SplitPort);
			} else if (OrIndex == -1 && AndIndex != -1) {
				SplitIP = pFilter.Mid(0, AndIndex);
				SplitPort = pFilter.Mid(AndIndex + 5, FilterLength - AndIndex - 5);

				SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
				SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
				FilterAndVec.push_back(SplitIP);
				FilterAndVec.push_back(SplitPort);
			}
		} else {
			result = FALSE;
		}
	} else if (SplitPort == L"PORT == ") {
		if (FilterLength >= 9 && FilterLength <= 13) {
			SplitPort = pFilter.Mid(8, FilterLength - 8);
			FilterSingleVec.push_back(SplitPort);
		} else if (FilterLength >= 26 && FilterLength <= 39) {
			if (OrIndex != -1 && AndIndex == -1) {
				SplitPort = pFilter.Mid(0, OrIndex);
				SplitIP = pFilter.Mid(OrIndex + 4, FilterLength - OrIndex - 4);

				SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
				SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
				FilterOrVec.push_back(SplitIP);
				FilterOrVec.push_back(SplitPort);
			} else if (OrIndex == -1 && AndIndex != -1) {
				SplitPort = pFilter.Mid(0, AndIndex);
				SplitIP = pFilter.Mid(AndIndex + 5, FilterLength - AndIndex - 5);

				SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
				SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
				FilterAndVec.push_back(SplitIP);
				FilterAndVec.push_back(SplitPort);
			}
		} else {
			result = FALSE;
		}
	} else if (SplitBracket == L"(") {
		/*
		(ip == 0.0.0.0 or port == 1) and tcp  - 36
		(ip == 123.123.123.123 and port == 65536) and icmp  - 50

		(port == 1 or ip == 0.0.0.0) and tcp  - 36
		(port == 65536 and ip == 123.123.123.123) and icmp   - 50
		*/
		int EndBracketIndex = pFilter.Find(L")");

		if (FilterLength >= 36 && FilterLength <= 50) {
			if (SplitIP == L"(IP ==") {
				CString BracketBlock = pFilter.Mid(0, EndBracketIndex);
				CString ProtocolBlock = pFilter.Mid(EndBracketIndex + 1, pFilter.GetLength());

				SplitProtocol = ProtocolBlock.Mid(5, ProtocolBlock.GetLength());

				BracketBlock.Replace(L"(", L"");
				BracketBlock.Replace(L")", L"");

				int BrracketBlockLength = BracketBlock.GetLength();
				int BracketOrIndex = BracketBlock.Find(L" OR ");
				int BracketAndIndex = BracketBlock.Find(L" AND ");

				if (BracketOrIndex != -1 && BracketAndIndex == -1) {
					SplitIP = BracketBlock.Mid(0, BracketOrIndex);
					SplitPort = BracketBlock.Mid(BracketOrIndex + 4, BrracketBlockLength - BracketOrIndex - 4);

					SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
					SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);

					FilterOrAndVec.push_back(SplitIP);
					FilterOrAndVec.push_back(SplitPort);
					FilterOrAndVec.push_back(SplitProtocol);
				} else if (BracketOrIndex == -1 && BracketAndIndex != -1) {
					SplitIP = BracketBlock.Mid(0, BracketAndIndex);
					SplitPort = BracketBlock.Mid(BracketAndIndex + 5, FilterLength - BracketAndIndex - 5);

					SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
					SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
					FilterAndAndVec.push_back(SplitIP);
					FilterAndAndVec.push_back(SplitPort);
					FilterAndAndVec.push_back(SplitProtocol);
				}
			} else if (SplitPort == L"(PORT ==") {
				CString BracketBlock = pFilter.Mid(0, EndBracketIndex);
				CString ProtocolBlock = pFilter.Mid(EndBracketIndex + 1, pFilter.GetLength());

				SplitProtocol = ProtocolBlock.Mid(5, ProtocolBlock.GetLength());

				BracketBlock.Replace(L"(", L"");
				BracketBlock.Replace(L")", L"");

				int BrracketBlockLength = BracketBlock.GetLength();
				int BracketOrIndex = BracketBlock.Find(L" OR ");
				int BracketAndIndex = BracketBlock.Find(L" AND ");

				if (BracketOrIndex != -1 && BracketAndIndex == -1) {
					SplitPort = BracketBlock.Mid(0, BracketOrIndex);
					SplitIP = BracketBlock.Mid(BracketOrIndex + 4, BrracketBlockLength - BracketOrIndex - 4);

					SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
					SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);

					FilterOrAndVec.push_back(SplitIP);
					FilterOrAndVec.push_back(SplitPort);
					FilterOrAndVec.push_back(SplitProtocol);
				} else if (BracketOrIndex == -1 && BracketAndIndex != -1) {
					SplitPort = BracketBlock.Mid(0, BracketAndIndex);
					SplitIP = BracketBlock.Mid(BracketAndIndex + 5, FilterLength - BracketAndIndex - 5);

					SplitIP = SplitIP.Mid(6, SplitIP.GetLength() - 6);
					SplitPort = SplitPort.Mid(8, SplitPort.GetLength() - 8);
					FilterAndAndVec.push_back(SplitIP);
					FilterAndAndVec.push_back(SplitPort);
					FilterAndAndVec.push_back(SplitProtocol);
				}
			}
		}


	} else {
		result = FALSE;
	}

	if (!FilterSingleVec.empty()) {
		if (SIP == SplitIP || DIP == SplitIP || SPORT == SplitPort || DPORT == SplitPort) {
			result = TRUE;
		} else {
			result = FALSE;
		}
	} else if (!FilterOrVec.empty()) {
		if (SIP == SplitIP || DIP == SplitIP || SPORT == SplitPort || DPORT == SplitPort) {
			result = TRUE;
		} else {
			result = FALSE;
		}
	} else if (!FilterAndVec.empty()) {
		if (SIP == SplitIP && SPORT == SplitPort) {
			result = TRUE;
		} else if (SIP == SplitIP && DPORT == SplitPort) {
			result = TRUE;
		} else if (DIP == SplitIP && SPORT == SplitPort) {
			result = TRUE;
		} else if (DIP == SplitIP && DPORT == SplitPort) {
			result = TRUE;
		} else {
			result = FALSE;
		}
	} else if (!FilterOrAndVec.empty()) {
		if (SIP == SplitIP || DIP == SplitIP || SPORT == SplitPort || DPORT == SplitPort) {
			if (PROTOCOL == SplitProtocol) {
				result = TRUE;
			}
		} else {
			result = FALSE;
		}
	} else if (!FilterAndAndVec.empty()) {
		if (SIP == SplitIP && SPORT == SplitPort) {
			result = TRUE;
		} else if (SIP == SplitIP && DPORT == SplitPort) {
			result = TRUE;
		} else if (DIP == SplitIP && SPORT == SplitPort) {
			result = TRUE;
		} else if (DIP == SplitIP && DPORT == SplitPort) {
			result = TRUE;
		} else {
			result = FALSE;
		}

		if (result) {
			if (PROTOCOL == SplitProtocol) {
				result = TRUE;
			} else {
				result = FALSE;
			}
		}
	}

	return result;
}



int Filter::FilterFunction::GetCountStr(CString target_str, CString target_find_str) {
	target_str = target_str.MakeUpper();
	target_str = target_str.TrimLeft();
	target_str = target_str.TrimRight();

	int op = 0;
	int op_cnt = 0;

	op = target_str.Find(target_find_str);
	while (op != -1) {
		op_cnt++;
		op = target_str.Find(target_find_str, op + 1);
	}

	return op_cnt;
}

std::vector<int> Filter::FilterFunction::GetCountStrIdx(CString target_str, CString target_find_str) {
	std::vector<int> result_vec;

	target_str = target_str.MakeUpper();
	target_str = target_str.TrimLeft();
	target_str = target_str.TrimRight();

	int op = 0;

	op = target_str.Find(target_find_str);
	while (op != -1) {
		result_vec.push_back(op);
		op = target_str.Find(target_find_str, op + 1);
	}

	return result_vec;
}


std::vector<CString> Filter::FilterFunction::SplitStr(CString target_str, CString target_find_str) {
	std::vector<CString> result_vec;
	int op_cnt = GetCountStr(target_str, target_find_str);
	std::vector<int> index_vec = GetCountStrIdx(target_str, target_find_str);

	int start_pos = 0;
	int end_pos = 0;

	if (!index_vec.empty()) {
		end_pos = index_vec[0];
	}

	for (int i = 0; i < op_cnt; i++) {
		CString tempStr = target_str.Mid(start_pos, end_pos - start_pos);
		tempStr = tempStr.TrimLeft();
		tempStr = tempStr.TrimRight();
		result_vec.push_back(tempStr);
		start_pos = end_pos + target_find_str.GetLength();
		if (i == op_cnt - 1) {
			end_pos = target_str.GetLength();
			result_vec.push_back(target_str.Mid(start_pos, end_pos - start_pos).TrimLeft().TrimRight());
		} else {
			end_pos = index_vec[i + 1];
		}
	}


	return result_vec;
}



BOOL  Filter::FilterFunction::FilterValidCheckFunction(CString Filter) {
	BOOL result = FALSE;
	CString temp_filter = Filter;
	CString default_filter = Filter::FilterFunction::DefaultFilterValue;
	int FilterLength = Filter.GetLength();
	temp_filter = temp_filter.MakeUpper();
	temp_filter = temp_filter.TrimLeft();
	temp_filter = temp_filter.TrimRight();

	// 필터 유효값 확인
	if (temp_filter == L"" || temp_filter == default_filter.MakeUpper()) {
		result = TRUE;
		return result;
	}
	/*
	length == 6
	length < 6
	*/
	if (temp_filter.Mid(0, 6) == L"LENGTH") {
		CString Operate = temp_filter.Mid(6, 3);
		Operate = Operate.TrimLeft();
		Operate = Operate.TrimRight();

		if (Operate != L"==" && Operate != L"<=" && Operate != L">=" && Operate != L"<" && Operate != L">") {
			result = FALSE;
			return result;
		}

		CString Value = temp_filter.Mid(9, temp_filter.GetLength()-9);
		Value = Value.TrimLeft();
		Value = Value.TrimRight();
		if (Data::DataFunction::IsNumeric(Value)) {
			result = TRUE;
			return result;
		}
	}
	int tmep_FilterLength = temp_filter.GetLength();
	if (tmep_FilterLength == 3 || tmep_FilterLength == 4) {
		if (temp_filter == L"TCP" || temp_filter == L"UDP" || temp_filter == L"ARP" || temp_filter == "ICMP") {
			result = TRUE;
			return result;
		}
	} else if (tmep_FilterLength == 10 || tmep_FilterLength == 11) {
		CT2CA str_temp_filter(temp_filter);
		std::string str_temp_filter_regex(str_temp_filter);
		std::regex target_regex("(?:(?:TCP|UDP|ARP|ICMP?) OR ){1}(?:TCP|UDP|ARP|ICMP?)");
		if (std::regex_match(str_temp_filter_regex, target_regex)) {
			result = TRUE;
			return result;
		}
	} else if (tmep_FilterLength == 17 || tmep_FilterLength == 18) {
		CT2CA str_temp_filter(temp_filter);
		std::string str_temp_filter_regex(str_temp_filter);
		std::regex target_regex("(?:(?:TCP|UDP|ARP|ICMP?) OR ){2}(?:TCP|UDP|ARP|ICMP?)");
		if (std::regex_match(str_temp_filter_regex, target_regex)) {
			result = TRUE;
			return result;
		}
	} else if (tmep_FilterLength == 25) {
		CT2CA str_temp_filter(temp_filter);
		std::string str_temp_filter_regex(str_temp_filter);
		std::regex target_regex("\(?:(?:TCP|UDP|ARP|ICMP?) OR ){3}(?:TCP|UDP|ARP|ICMP?)");
		if (std::regex_match(str_temp_filter_regex, target_regex)) {
			result = TRUE;
			return result;
		}
	}




	if (temp_filter.Mid(0, 8) == L"PORT == "){
		CString port_number = temp_filter.Mid(8, temp_filter.GetLength() - 8);
		int ORcnt = GetCountStr(port_number, L"OR");
		int ANDcnt = GetCountStr(port_number, L"AND");

		if (ORcnt == 0 && ANDcnt == 0) {
			if (Data::DataFunction::IsNumeric(port_number)) {
				result = TRUE;
				return result;
			}
		} else if (ORcnt == 1 && ANDcnt == 0) {
			int ORindex = port_number.Find(L"OR");
			CString port = port_number.Mid(0, ORindex-1);
			if (!Data::DataFunction::IsNumeric(port)) {
				result = FALSE;
				return result;
			}
			CString IPstr = port_number.Mid(ORindex, port_number.GetLength() - ORindex);
			IPstr.TrimLeft();
			IPstr.TrimRight();

			CString IPaddr = IPstr.Mid(8, IPstr.GetLength() - 8);
			IPaddr.TrimLeft();
			IPaddr.TrimRight();

			CT2CA pszConvertedAnsiString(IPaddr);
			std::string ip_regex(pszConvertedAnsiString);
			std::regex target_regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

			if (std::regex_match(ip_regex, target_regex)) {
				result = TRUE;
				return result;
			}
		} else if (ORcnt == 0 && ANDcnt == 1) {
			int ANDindex = port_number.Find(L"AND");
			CString port = port_number.Mid(0, ANDindex-1);
			if (!Data::DataFunction::IsNumeric(port)) {
				result = FALSE;
				return result;
			}
			CString IPstr = port_number.Mid(ANDindex, port_number.GetLength() - ANDindex);
			IPstr.TrimLeft();
			IPstr.TrimRight();

			CString IPaddr = IPstr.Mid(10, IPstr.GetLength() - 10);
			IPaddr.TrimLeft();
			IPaddr.TrimRight();

			CT2CA pszConvertedAnsiString(IPaddr);
			std::string ip_regex(pszConvertedAnsiString);
			std::regex target_regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

			if (std::regex_match(ip_regex, target_regex)) {
				result = TRUE;
				return result;
			}
		}
	}

	if (temp_filter.Mid(0, 6) == L"IP == ") {
		CString ip_addr = temp_filter.Mid(6, temp_filter.GetLength() - 6);
		int ORcnt = GetCountStr(ip_addr, L" OR ");
		int ANDcnt = GetCountStr(ip_addr, L"AND");

		if (ORcnt == 0 && ANDcnt == 0) {
			CString IPaddr = ip_addr;
			IPaddr.TrimLeft();
			IPaddr.TrimRight();

			CT2CA pszConvertedAnsiString(IPaddr);
			std::string ip_regex(pszConvertedAnsiString);
			std::regex target_regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
			if (std::regex_match(ip_regex, target_regex)) {
				result = TRUE;
				return result;
			}
		} else if (ORcnt == 1 && ANDcnt == 0) {
			int ORindex = ip_addr.Find(L"OR");
			CString tmp_ip = ip_addr.Mid(0, ORindex - 1);
			CT2CA pszConvertedAnsiString(tmp_ip);
			std::string ip_regex(pszConvertedAnsiString);
			std::regex target_regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
			if (!std::regex_match(ip_regex, target_regex)) {
				result = FALSE;
				return result;
			}

			CString port = ip_addr.Mid(ORindex, ip_addr.GetLength());
			port = port.Mid(10, port.GetLength() - 10);
			port.TrimLeft();
			port.TrimRight();

			if (Data::DataFunction::IsNumeric(port)) {
				result = TRUE;
				return result;
			}
		} else if (ANDcnt == 1 && ORcnt == 0) {
			int ANDindex = ip_addr.Find(L"AND");
			CString tmp_ip = ip_addr.Mid(0, ANDindex - 1);
			CT2CA pszConvertedAnsiString(tmp_ip);
			std::string ip_regex(pszConvertedAnsiString);
			std::regex target_regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
			if (!std::regex_match(ip_regex, target_regex)) {
				result = FALSE;
				return result;
			}

			CString port = ip_addr.Mid(ANDindex, ip_addr.GetLength());
			port = port.Mid(11, port.GetLength() - 11);
			port.TrimLeft();
			port.TrimRight();

			if (Data::DataFunction::IsNumeric(port)) {
				result = TRUE;
				return result;
			}
		}
	}


	/*
	포트번호로 시작
	port == 1    -   9
	port == 65536    -  13
	port ==  1 or ip == 0.0.0.0   - 26
	port == 65536 and ip == 123.123.123.123  - 39


	아이피로 시작
	ip == 0.0.0.0    - 13
	ip == 123.123.123.123  - 21
	ip == 0.0.0.0 or port == 1   - 26
	ip == 123.123.123.123 and port == 65536  - 39


	(ip == 0.0.0.0 or port == 1) and tcp  - 36
	(ip == 123.123.123.123 and port == 65536) and icmp  - 50
	(port == 1 or ip == 0.0.0.0) and tcp  - 36
	(port == 65536 and ip == 123.123.123.123) and icmp   - 50
	*/

	return result;
}