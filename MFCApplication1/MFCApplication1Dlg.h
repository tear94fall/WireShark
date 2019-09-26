
// MFCApplication1Dlg.h: 헤더 파일
//

#pragma once


typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)  
	u_char tos; // Type of service   
	u_short tlen; // Total length   
	u_short identification; // Identification  
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)  
	u_char ttl; // Time to live  
	u_char proto; // Protocol  
	u_short crc; // Header checksum  
	ip_address saddr; // Source address  
	ip_address daddr; // Destination address  
	u_int op_pad; // Option + Padding  
}ip_header;

typedef struct udp_header {
	u_short sport;   // Source port  
	u_short dport;   // Destination port  
	u_short len;   // Datagram length  
	u_short crc;   // Checksum  
}udp_header;

typedef struct ether_header {
	u_char dst_host[6];
	u_char src_host[6];
	u_short frame_type;
}ether_header;

typedef struct tcp_header {
	u_short sport; // Source port  
	u_short dport; // Destination port  
	u_int seqnum; // Sequence Number  
	u_int acknum; // Acknowledgement number  
	u_char hlen; // Header length  
	u_char flags; // packet flags  
	u_short win; // Window size  
	u_short crc; // Header Checksum  
	u_short urgptr; // Urgent pointer...still don't know what this is...  
}tcp_header;

typedef struct icmp_header {
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short seq;
}icmp_header;

// CMFCApplication1Dlg 대화 상자
class CMFCApplication1Dlg : public CDialogEx
{
// 생성입니다.
public:
	CMFCApplication1Dlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.

	enum ThreadWorking {
		STOP = 0,
		RUNNING = 1,
		PAUSE = 2
	};

	bool m_bThreadStart = false;
	CWinThread* m_pThread = NULL;
	ThreadWorking m_ThreadWorkType = STOP;

	static UINT ThreadFunctionFirstTest(LPVOID _mothod);

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
	CListCtrl m_ListCtrl;
	afx_msg void OnBnClickedButton1();
	CListBox m_HexEditorList;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
//	CButton puase_button;
	CButton pause_button;
	void CMFCApplication1Dlg::ChangeStaticText(int all_pkt_cnt, int tcp_pkt_cnt, int udp_pkt_cnt, int arp_pkt_cnt, int icmp_pkt_cnt);
	void ClearPacketCnt();
	CString GetIPAddr(ip_address ip_addr);
	afx_msg void OnCustomdrawList(NMHDR* pNMHDR, LRESULT* pResult);
};
