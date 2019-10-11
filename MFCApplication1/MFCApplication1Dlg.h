
// MFCApplication1Dlg.h: 헤더 파일
//

#pragma once
#include "NetworkInterfaceDlg.h"
#include "ProtocolHeader.hpp"
#include <cstring>
#include <string>
#include <thread>
#include <sstream>
#include <pcap.h>
#include <map>
#include <vector>
#include <iomanip>
#include <string>
#include <afxmt.h>
#include <afxwin.h>
#include <iostream>
#include <fstream>

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

// CMFCApplication1Dlg 대화 상자
class CMFCApplication1Dlg : public CDialogEx {
	// 생성입니다.
public:
	CMFCApplication1Dlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.
	// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION1_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	enum ThreadWorking {
		STOP = 0,
		RUNNING = 1,
		PAUSE = 2
	};

	struct SORTPARAM {
		int iSrotColumn;
		bool bSortDirect;
		CListCtrl* pList;
	};

	int end_pos = 0, start_pos = 0;
	long file_length;
	char* file_buffer;
	CString file_name_read;
	char* file_name_write = "temp.dat";
	bool is_file_save = false;

	bool m_bThreadStart = false;
	CWinThread* m_pThread = NULL;
	ThreadWorking m_ThreadWorkType = STOP;
	static UINT ThreadFunctionFirstTest(LPVOID _mothod);

	CWinThread* m_pThread123 = NULL;
	ThreadWorking m_ThreadWorkType123 = STOP;
	static UINT ThreadFunctionSecondTest(LPVOID _mothod);

	int packet_cnt = 0;
	int tcp_pkt_cnt = 0;
	int udp_pkt_cnt = 0;
	int arp_pkt_cnt = 0;
	int icmp_pkt_cnt = 0;

	NetworkInterfaceDlg netInterfaceDlg;
	CString m_strSelectedNetworkInterface;
	BOOL m_bAscending = false;

	CString Filter;
	bool IsFilterApply = false;

	CTreeCtrl PacketDataCtrl;
	CListCtrl PacketDumpList;
	CEdit m_FilterEditCtrl;
	CListCtrl m_ListCtrl;
	CListBox m_HexEditorList;
	CButton pause_button;

	virtual BOOL PreTranslateMessage(MSG* pMsg);

	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();

	afx_msg void OnCustomdrawList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnHdnItemclick(NMHDR* pNMHDR, LRESULT* Result);
	static int CALLBACK SortFuncStr(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
	static int CALLBACK SortFuncNum(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

	void ChangeStaticText(int all_pkt_cnt, int tcp_pkt_cnt, int udp_pkt_cnt, int arp_pkt_cnt, int icmp_pkt_cnt);
	void ClearPacketCnt();
	void SetData(CString FrameNumber, CString Time, CString Source, CString Destination, CString Protocol, CString Length, CString Info, CString Packet_Dump_Data);
	std::string GetCurrentTimeStr();

	CString HexToDec(CString _number);
	CString HexToBinary(CString _number);
	CString GetTCPFlagToBin(CString _Flag);
	CString GetTCPFlagToStr(CString _Flag);
	CString GetTCPFlagToLongStr(CString _Flag);
	CString GetIPAddr(ip_address ip_addr);
	CString GetFlagSetNotSet(CString _Flag);
	CString Calculate4HexNumber(CString num1, CString num2, CString num3, CString num4);
	CString Calculate2HexNumber(CString num1, CString num2);
	CString MakeIPAddressV6(CString Aclass, CString Bclass, CString Cclass, CString Dclass, CString Eclass, CString Fclass);
	CString ChangeHexToAscii(CString HexData);
	CString ArpOpcde(CString OpcodeNumber);
	CString ArpHardwareType(CString HardwareTypeNumber);
	void OpenPacketDataFile();
	afx_msg void FileSave();
};