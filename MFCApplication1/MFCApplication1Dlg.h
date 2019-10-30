
// MFCApplication1Dlg.h: 헤더 파일
//

#pragma once
#include "NetworkInterfaceDlg.h"
#include "ProtocolHeader.hpp"

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

	Protocol::IP::ip_header* ip_hdr;
	Protocol::UDP::udp_header* udp_hdr;
	Protocol::TCP::tcp_header* tcp_hdr;
	Protocol::ICMP::icmp_header* icmp_hdr;
	Protocol::ARP::arp_header* arp_hdr = NULL;
	Protocol::ETHERNET::ether_header* eth_hdr;

	u_int ip_len;
	const pcap_pkthdr* m_header;
	pcap_t* target_adhandle;
	const u_char* m_pkt_data;

	CString CurrentTimeStr;
	CString source_ip;
	CString destionation_ip;
	CString Protocol;
	CString Length;
	std::string packet_dump_data_string;  

	int end_pos = 0, start_pos = 0;
	long file_length = 0;
	char* file_buffer = NULL;
	CString file_name_read;
	char* file_name_write = "temp.dat";
	CString file_name_cstr = L"temp.dat";
	std::vector<CString> FileList;

	bool is_file_save = false;
	int packet_count_per_file = 500;

	bool m_bThreadStart = false;
	CWinThread* m_PacketCaptrueThread = NULL;
	ThreadWorking m_PacketCaptureThreadWorkType = STOP;
	static UINT PacketCaptureThreadFunction(LPVOID _mothod);

	CWinThread* m_FileReadThread = NULL;
	ThreadWorking m_FileReadThreadWorkType = STOP;
	static UINT FileReadThreadFunction(LPVOID _mothod);

	CWinThread* m_FileOpenThread = NULL;
	ThreadWorking m_FileOpenThreadWorkType = STOP;
	static UINT FileOpenThreadFunction(LPVOID _mothod);

	BOOL isFileWriteEnd = FALSE;

	std::mutex mutex;
	BOOL is_UpdateFilter = FALSE;

	BOOL CursorPositionLast = TRUE;

	BOOL is_PktCapThreadStart = FALSE;
	BOOL is_FileReadThreadStart = FALSE;
	BOOL is_FileOpenThreadStart = FALSE;
	BOOL m_FilterThreadEnd = FALSE;

	NetworkInterfaceDlg netInterfaceDlg;
	CString m_strSelectedNetworkInterface;
	BOOL m_bAscending = false;

	int PrevClickColumnNumber = -1;

	CListCtrl m_PacketCapturedListCtrl;
	CListCtrl m_PacketDumpListCtrl;
	CTreeCtrl m_PacketDataTreeCtrl;

	CEdit m_FilterEditCtrl;
	CButton pause_button;

	virtual BOOL PreTranslateMessage(MSG* pMsg);

	afx_msg void OnBnClickedCaptureStartButton();
	afx_msg void OnBnClickedCaptureQuitButton();
	afx_msg void OnBnClickedCapturePauseButton();
	afx_msg void OnBnClickedFilterApplyButton();
	afx_msg void OnClose();
	afx_msg void OnBnClickedCheck2();
	afx_msg void OnHdnItemclickList2(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void SetCursorPosition();

	void ChangeStaticText(int all_pkt_cnt, int tcp_pkt_cnt, int udp_pkt_cnt, int arp_pkt_cnt, int icmp_pkt_cnt);
	void OpenPacketDataFile();
	void FileSave();
	void SetDataToPacketData(CString FrameNumber, CString Time, CString Source, CString Destination, CString Protocol, CString Length, CString Info, CString Packet_Dump_Data);
	void SetDataToHDXEditor(CString ALLPacketData);
	void OnCustomdrawList(NMHDR* pNMHDR, LRESULT* pResult);
	void OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult);
	void OnHdnItemclick(NMHDR* pNMHDR, LRESULT* Result);
	void FileWriterFunction(char* file_name);
	void Wait(DWORD dwMillisecond);

	static int CALLBACK SortFuncStr(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
	static int CALLBACK SortFuncNum(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

	BOOL RemoveMouseMessage(void);
};
