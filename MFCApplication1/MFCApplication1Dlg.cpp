
// MFCApplication1Dlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"
#include "Resource.h"
#include "NetworkInterfaceDlg.h"

#include <thread>
#include <sstream>
#include <pcap.h>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
std::string GetCurrentTimeStr(void);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 대화 상자



CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_ListCtrl);
	DDX_Control(pDX, IDC_BUTTON3, pause_button);
	DDX_Control(pDX, IDC_TREE1, PacketDataCtrl);
	DDX_Control(pDX, IDC_LIST1, PacketDumpList);
	DDX_Control(pDX, IDC_EDIT1, m_FilterEditCtrl);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication1Dlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication1Dlg::OnBnClickedButton3)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, OnCustomdrawList)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST2, &CMFCApplication1Dlg::OnNMDblclkList2)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &CMFCApplication1Dlg::OnHdnItemclick)
//	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CMFCApplication1Dlg::OnNMCustomdrawList1)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 메시지 처리기

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	netInterfaceDlg.DoModal();
	bool cancelButtonClickedChecker = netInterfaceDlg.CancelButtonClickedFunction();

	if (cancelButtonClickedChecker) {
		::PostQuitMessage(WM_QUIT);
		netInterfaceDlg.EndDialog(IDOK);
		//DestroyWindow();
	}

	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.





	CButton* pButton = (CButton*)GetDlgItem(IDC_BUTTON2);
	pButton->EnableWindow(FALSE);

	CButton* pButton3 = (CButton*)GetDlgItem(IDC_BUTTON3);
	pButton3->EnableWindow(FALSE);

	SetWindowText(_T("Wire Dolphin "));

	m_FilterEditCtrl.SetWindowTextW(L"Enter filters...");

	CRect rt;
	m_ListCtrl.GetWindowRect(&rt);
	m_ListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	LV_COLUMN add_column;
	// 컬럼 속성을 지정한다. 텍스트 형식을 사용하고 폭을 명시하겠다고 설정한다.

	add_column.mask = LVCF_TEXT | LVCF_WIDTH;

	LPWSTR column_name[9] = { L"No",L"Time", L"Source", L"Destination", L"Protocol", L"Length", L"Info" ,L"Dump Data" };
	int count = 0;
	double column_width[9] = { 0.1, 0.17, 0.15, 0.15, 0.075, 0.075, 0.28, 0 };

	for (int i = 0; i < 8; i++) {
		add_column.pszText = column_name[i];
		add_column.cx = rt.Width() * column_width[i];
		m_ListCtrl.InsertColumn(i, &add_column);
	}

	PacketDumpList.GetWindowRect(&rt);
	PacketDumpList.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	// 컬럼 속성을 지정한다. 텍스트 형식을 사용하고 폭을 명시하겠다고 설정한다.

	add_column.mask = LVCF_TEXT | LVCF_WIDTH;
	LPWSTR packet_dump_header[4] = { L"Seq",L"Hex 1",L"HEX 2", L"ASCII" };
	double pakcet_dump_header_width[4] = { 0.1,0.27,0.27,0.3 };

	for (int i = 0; i < 4; i++) {
		add_column.pszText = packet_dump_header[i];
		add_column.cx = rt.Width() * pakcet_dump_header_width[i];
		PacketDumpList.InsertColumn(i, &add_column);
	}
	// 패킷의 갯수 카운트
	ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);




	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void CMFCApplication1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CMFCApplication1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCApplication1Dlg::OnBnClickedButton1()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (m_pThread == NULL) {
		m_pThread = AfxBeginThread(ThreadFunctionFirstTest, this);
		//AfxMessageBox(_T("캡처를 시작합니다"));
		CButton* pButton = (CButton*)GetDlgItem(IDC_BUTTON1);
		pButton->EnableWindow(FALSE);

		CButton* pButton2 = (CButton*)GetDlgItem(IDC_BUTTON2);
		pButton2->EnableWindow(TRUE);

		CButton* pButton3 = (CButton*)GetDlgItem(IDC_BUTTON3);
		pButton3->EnableWindow(TRUE);

		if (m_pThread == NULL) {
			AfxMessageBox(_T("Error!!!"));
		}

		m_pThread->m_bAutoDelete = FALSE;
		m_ThreadWorkType = RUNNING;



	}
	else {
		if (m_ThreadWorkType == RUNNING || m_ThreadWorkType == PAUSE) {
			//m_pThread->ResumeThread();
			//m_ThreadWorkType = RUNNING;
		}
	}
}


UINT CMFCApplication1Dlg::ThreadFunctionFirstTest(LPVOID _mothod) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	const char* filter = "tcp or udp or arp or icmp";
	//const char* filter = "arp or tcp or udp or icmp";
	struct bpf_program fcode;
	bpf_u_int32 NetMask;

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);

		if (d->description) {
			printf(" (%s)\n", d->description);
		}
		else {
			printf(" (No description available)\n");
		}
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	//scanf("%d", &inum);
	inum = pDlg->netInterfaceDlg.m_nSelectedIndex + 1;
	pDlg->m_strSelectedNetworkInterface = pDlg->netInterfaceDlg.InterfaceDescription;

	pDlg->SetDlgItemText(IDC_STATIC_NET,L"Interface: "+pDlg->m_strSelectedNetworkInterface);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	NetMask = 0xffffff;
	if (pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0) {
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
		pcap_close(adhandle);
		return -3;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter\n");
		pcap_close(adhandle);
		return -4;
	}

	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	int i;
	ip_header* ih;
	udp_header* uh;
	tcp_header* th;
	icmp_header* icmp_hdr;
	arp_header* arp_hdr = NULL;
	u_int ip_len;
	ether_header* ethhdr;

	ethhdr = (ether_header*)pkt_data;

	ih = (ip_header*)(pkt_data + 14);
	ip_len = (ih->ver_ihl & 0xf) * 4;

	int size = sizeof(pkt_data);

	if (ntohs(ethhdr->frame_type) == 0x0800) {
		if (ih->proto == IPPROTO_TCP) {
			// TCP
			th = (tcp_header*)((u_char*)ih + ip_len);

			CString source_ip = pDlg->GetIPAddr(ih->saddr);
			CString destionation_ip = pDlg->GetIPAddr(ih->daddr);

			int column_count = pDlg->m_ListCtrl.GetItemCount();

			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);
			pDlg->m_ListCtrl.InsertItem(column_count, column_count_str);


			pDlg->m_ListCtrl.SetItem(column_count, 1, LVIF_TEXT, CString(GetCurrentTimeStr().c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 2, LVIF_TEXT, source_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 3, LVIF_TEXT, destionation_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 4, LVIF_TEXT, _T("TCP"), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 5, LVIF_TEXT, (CString)(std::to_string(header->caplen).c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(htons(th->sport)).c_str())
				+ " -> " +
				(CString)(std::to_string(ntohs(th->dport)).c_str())
				, NULL, NULL, NULL, NULL);

			++pDlg->tcp_pkt_cnt;
			++pDlg->packet_cnt;

			pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);
		}
		else if (ih->proto == 4) {
			printf("IP\n");
		}
		else if (ih->proto == IPPROTO_UDP) {
			// UDP

			uh = (udp_header*)((u_char*)ih + ip_len);

			CString source_ip = pDlg->GetIPAddr(ih->saddr);
			CString destionation_ip = pDlg->GetIPAddr(ih->daddr);

			int column_count = pDlg->m_ListCtrl.GetItemCount();

			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);
			pDlg->m_ListCtrl.InsertItem(column_count, column_count_str);

			pDlg->m_ListCtrl.SetItem(column_count, 1, LVIF_TEXT, CString(GetCurrentTimeStr().c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 2, LVIF_TEXT, source_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 3, LVIF_TEXT, destionation_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 4, LVIF_TEXT, _T("UDP"), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 5, LVIF_TEXT, (CString)(std::to_string(header->caplen).c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(htons(uh->sport)).c_str())
				+ " -> " +
				(CString)(std::to_string(ntohs(uh->dport)).c_str())
				, NULL, NULL, NULL, NULL);

			++pDlg->udp_pkt_cnt;
			++pDlg->packet_cnt;
			pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);
		}
		else if (ih->proto == IPPROTO_ICMP) {
			// ICMP

			icmp_hdr = (icmp_header*)(ih + ip_len);

			CString source_ip = pDlg->GetIPAddr(ih->saddr);
			CString destionation_ip = pDlg->GetIPAddr(ih->daddr);

			int column_count = pDlg->m_ListCtrl.GetItemCount();

			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);
			pDlg->m_ListCtrl.InsertItem(column_count, column_count_str);

			pDlg->m_ListCtrl.SetItem(column_count, 1, LVIF_TEXT, CString(GetCurrentTimeStr().c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 2, LVIF_TEXT, source_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 3, LVIF_TEXT, destionation_ip, NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 4, LVIF_TEXT, _T("ICMP"), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 5, LVIF_TEXT, (CString)(std::to_string(header->caplen).c_str()), NULL, NULL, NULL, NULL);
			pDlg->m_ListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(icmp_hdr->code).c_str())
				, NULL, NULL, NULL, NULL);


			++pDlg->icmp_pkt_cnt;
			++pDlg->packet_cnt;
			pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);
		}
		else {
			printf("Unknown Protocol\n");
			unsigned char temp = ih->proto;

		}

		pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);

		int nCount = pDlg->m_ListCtrl.GetItemCount();
		pDlg->m_ListCtrl.EnsureVisible(nCount - 1, FALSE);


		std::string packet_dump_data;

		for (i = 1; (i < header->caplen + 1); i++) {
			char* temp = NULL;

			int temp2 = pkt_data[i - 1];

			std::stringstream stream;
			stream << std::hex << temp2;
			packet_dump_data += stream.str() + " ";

		}
	}
	else if (ntohs(ethhdr->frame_type) == 0x0806) {

	// ARP
	arp_hdr = (struct arp_header*)(pkt_data + 14);

	CString source_ip = pDlg->GetIPAddr(ih->saddr);
	CString destionation_ip = pDlg->GetIPAddr(ih->daddr);

	int column_count = pDlg->m_ListCtrl.GetItemCount();

	CString column_count_str;
	column_count_str.Format(_T("%d"), column_count + 1);
	pDlg->m_ListCtrl.InsertItem(column_count, column_count_str);

	char soure_hw_addr[4];
	char target_hw_addr[4];

	CString sender_hw_addr, target_hw_adr;
	for (int i = 0; i < 5; i++) {
		sprintf(soure_hw_addr, "%02x:", arp_hdr->sha[i]);
		sender_hw_addr += soure_hw_addr;

		sprintf(target_hw_addr, "%02x:", arp_hdr->tha[i]);
		target_hw_adr += target_hw_addr;
	}

	sprintf(soure_hw_addr, "%02x", arp_hdr->sha[5]);
	sender_hw_addr += soure_hw_addr;

	sprintf(target_hw_addr, "%02x", arp_hdr->tha[5]);
	target_hw_adr += target_hw_addr;


	pDlg->m_ListCtrl.SetItem(column_count, 1, LVIF_TEXT, CString(GetCurrentTimeStr().c_str()), NULL, NULL, NULL, NULL);
	pDlg->m_ListCtrl.SetItem(column_count, 2, LVIF_TEXT, source_ip, NULL, NULL, NULL, NULL);
	pDlg->m_ListCtrl.SetItem(column_count, 3, LVIF_TEXT, destionation_ip, NULL, NULL, NULL, NULL);
	pDlg->m_ListCtrl.SetItem(column_count, 4, LVIF_TEXT, _T("ARP"), NULL, NULL, NULL, NULL);
	pDlg->m_ListCtrl.SetItem(column_count, 5, LVIF_TEXT, (CString)(std::to_string(header->caplen).c_str()), NULL, NULL, NULL, NULL);
	pDlg->m_ListCtrl.SetItem(column_count, 6, LVIF_TEXT,
		sender_hw_addr + L" -> " + target_hw_adr
		, NULL, NULL, NULL, NULL);


	++pDlg->arp_pkt_cnt;
	++pDlg->packet_cnt;
	pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);
	}


	std::string result;

	for (i = 1; (i < header->caplen + 1); i++) {
		char* temp = NULL;

		int temp2 = pkt_data[i - 1];
		std::stringstream stream;
		stream << std::setw(2) << std::setfill('0') << std::hex << temp2;

		result += stream.str();
	}


	CString packet_dump_data(result.c_str());
	int column_count = pDlg->m_ListCtrl.GetItemCount()-1;
	pDlg->m_ListCtrl.SetItem(column_count, 7, LVIF_TEXT, packet_dump_data, NULL, NULL, NULL, NULL);


}

void CMFCApplication1Dlg::OnBnClickedButton2()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (m_pThread == NULL) {

	}
	else {
		m_pThread->SuspendThread();

		DWORD dwResult;
		::GetExitCodeThread(m_pThread->m_hThread, &dwResult);

		delete m_pThread;
		m_pThread = NULL;

		m_ThreadWorkType = STOP;

		CButton* pButton = (CButton*)GetDlgItem(IDC_BUTTON1);
		pButton->EnableWindow(TRUE);

		CButton* pButton2 = (CButton*)GetDlgItem(IDC_BUTTON2);
		pButton2->EnableWindow(FALSE);

		CButton* pButton3 = (CButton*)GetDlgItem(IDC_BUTTON3);
		pButton3->EnableWindow(FALSE);


		ClearPacketCnt();
		ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
		m_ListCtrl.DeleteAllItems();
		PacketDataCtrl.DeleteAllItems();
		PacketDumpList.DeleteAllItems();
	}
}

void CMFCApplication1Dlg::	ChangeStaticText(int all_pkt_cnt, int tcp_pkt_cnt, int udp_pkt_cnt, int arp_pkt_cnt, int icmp_pkt_cnt){
	SetDlgItemText(IDC_STATIC, 
		L"ALL : " + (CString)(std::to_string(all_pkt_cnt).c_str()) +
		L" TCP : " + (CString)(std::to_string(tcp_pkt_cnt).c_str()) +
		L" UDP : " + (CString)(std::to_string(udp_pkt_cnt).c_str()) +
		L" ARP : " + (CString)(std::to_string(arp_pkt_cnt).c_str()) +
		L" ICMP : " + (CString)(std::to_string(icmp_pkt_cnt).c_str())
	);
}

void CMFCApplication1Dlg::ClearPacketCnt() {
	packet_cnt = 0;
	tcp_pkt_cnt = 0;
	udp_pkt_cnt = 0;
	arp_pkt_cnt = 0;
	icmp_pkt_cnt = 0;
}

void CMFCApplication1Dlg::OnBnClickedButton3()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (m_pThread == NULL) {
	}
	else {
		if (m_ThreadWorkType == RUNNING) {
			pause_button.SetWindowText(L"Resume");
			m_pThread->SuspendThread();
			m_ThreadWorkType = PAUSE;
		}
		else {
			pause_button.SetWindowText(L"Pause");
			m_pThread->ResumeThread();
			m_ThreadWorkType = RUNNING;
		}
	}
}


std::string GetCurrentTimeStr(void) {
	time_t     tm_time;
	struct tm* st_time;
	char       buff[1024];

	time(&tm_time);
	st_time = localtime(&tm_time);
	strftime(buff, 1024, "%Y-%m-%d %p %H:%M:%S", st_time);

	std::string temp_buf = buff;

	return temp_buf;
}


CString CMFCApplication1Dlg::GetIPAddr(ip_address ip_addr) {
	CString temp_ip_addr;
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte1)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte2)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte3)).c_str()) + L".";
	temp_ip_addr += CString(std::to_string(int(ip_addr.byte4)).c_str());

	return temp_ip_addr;
}

void CMFCApplication1Dlg::OnCustomdrawList(NMHDR* pNMHDR, LRESULT* pResult) {

	LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	NMLVCUSTOMDRAW* pLVCD = (NMLVCUSTOMDRAW*)pNMHDR;

	*pResult = 0;

	if (CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage) {
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage)
	{
		if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"TCP") {
			//pLVCD->clrText = RGB(0, 0, 0, );  // 글자 색 변경
			pLVCD->clrTextBk = RGB(231, 230, 255); // 배경 색 변경 
		}
		else if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"UDP") {
			pLVCD->clrTextBk = RGB(218, 238, 255);
		}
		else if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"ICMP") {
			pLVCD->clrTextBk = RGB(252, 224, 255);
		}
		else if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"ARP") {
			pLVCD->clrTextBk = RGB(250, 240, 215);
		}

		*pResult = CDRF_DODEFAULT;
	}
}

void CMFCApplication1Dlg::OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	*pResult = 0;

	pNMItemActivate->iItem;
	if (pNMItemActivate->iItem != -1) {
		CString FrameNumber = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 0);
		CString Time = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 1);
		CString Source = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 2);
		CString Destination = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 3);
		CString Protocol = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 4);
		CString Length = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 5);
		CString Info = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 6);
		CString Packet_Dump_Data = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 7);



		PacketDataCtrl.DeleteAllItems();
		PacketDataCtrl.Invalidate();

		//===========================================================
		CString PacketDataLine1;
		CString PacketDataLine2;
		CString PacketDataLine3;
		CString PacketDataLine4;

		PacketDataLine1 = L"Frame " + FrameNumber + L": "
			+ Length + L"bytes on wire (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits), "
			+ Length + L"bytes captured (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits) on interface 0";

		CString PakcetDataLine1by1 = L"Interface id: 0 (" + netInterfaceDlg.InterfaceName + L")";
		CString PakcetDataLine1by1by1 = L"Interface name: " + netInterfaceDlg.InterfaceName;
		CString PakcetDataLine1by1by2 = L"Interface desciption: " + netInterfaceDlg.InterfaceDescription;

		CString PakcetDataLine1by2 = L"Encapsulation type: Ethernet (1)";
		CString PakcetDataLine1by3 = L"Arrival Time: " + Time;
		CString PakcetDataLine1by4 = L"Frame Number: " + FrameNumber;
		CString PakcetDataLine1by5 = L"Frame Length: " + Length + L" bytes (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits)";
		CString PakcetDataLine1by6 = L"Capture Length: " + Length + L" bytes (" + CString(std::to_string(_ttoi(Length) * 8).c_str()) + L" bits)";


		CString Destination_addr = Packet_Dump_Data.Mid(0, 2) + L":"
			+ Packet_Dump_Data.Mid(2, 2) + L":"
			+ Packet_Dump_Data.Mid(4, 2) + L":"
			+ Packet_Dump_Data.Mid(6, 2) + L":"
			+ Packet_Dump_Data.Mid(8, 2) + L":"
			+ Packet_Dump_Data.Mid(10, 2);

		CString Source_addr = Packet_Dump_Data.Mid(12, 2) + L":"
			+ Packet_Dump_Data.Mid(14, 2) + L":"
			+ Packet_Dump_Data.Mid(16, 2) + L":"
			+ Packet_Dump_Data.Mid(18, 2) + L":"
			+ Packet_Dump_Data.Mid(20, 2) + L":"
			+ Packet_Dump_Data.Mid(22, 2);

		PacketDataLine2 = L"Ethernet ⅠⅠ, Src: " + Source_addr + L", Dst: " + Destination_addr;
		CString PakcetDataLine2by1 = L"Destination: " + Destination_addr;
		CString PakcetDataLine2by2 = L"Source: " + Source_addr;

		// IPv6 일때 작동하도록 수정
		CString PakcetDataLine2by3 = L"Type: IPv4 (0x" + Packet_Dump_Data.Mid(24, 2) + L")";
		CString PakcetDataLine2by4 = L"Padding: " + Packet_Dump_Data.Mid(108, 12);

		CString ipVersion = Packet_Dump_Data.Mid(28, 1);
		CString headerLength = Packet_Dump_Data.Mid(29, 1);


		CString totalLength = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(32, 1))) * 4096 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(33, 1))) * 256 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(34, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(35, 1))) * 1
				)).c_str());

		CString identification = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(36, 1))) * 4096 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(37, 1))) * 256 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(38, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(39, 1))) * 1
				)).c_str());

		CString timeToLive = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(44, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(45, 1))) * 1
				)).c_str());

		CString ptotocol = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(46, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(47, 1))) * 1
				)).c_str());

		PacketDataLine3 = L"Internet Protocol Version " + ipVersion + L", Src: " + Source + L", Dst: " + Destination;

		CString ipVersionBinary = HexToBinary(HexToDec(ipVersion));
		CString headerLengthBinary = HexToBinary(HexToDec(headerLength));

		CString PacketDataLine3by1 = ipVersionBinary + L"  . . . . = Version: " + ipVersion;
		CString PacketDataLine3by2 = L". . . .  " + headerLengthBinary + " = Header Length: " + CString(std::to_string((_ttoi(headerLength) * 4)).c_str()) + L" bytes (" + headerLength + L")";


		CString PacketDataLine3by3 = L"Differentinated Services Field: 0x" + Packet_Dump_Data.Mid(30, 2);
		CString PacketDataLine3by4 = L"Total Length: " + totalLength;
		CString PacketDataLine3by5 = L"Identification: 0x" + Packet_Dump_Data.Mid(36, 4) + L" (" + identification + L")";
		CString PacketDataLine3by6 = L"Flags: 0x" + Packet_Dump_Data.Mid(40, 4);
		CString PacketDataLine3by7 = L"Time to live: " + timeToLive;
		CString PacketDataLine3by8 = L"Protocol: " + Protocol + L"(" + ptotocol + L")";
		CString PacketDataLine3by9 = L"Header checksum: " + Packet_Dump_Data.Mid(48, 4); +L")";
		CString PacketDataLine3by10 = L"Source: " + Source;
		CString PacketDataLine3by11 = L"Destination: " + Destination;

		CString Line4SourcePort = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(68, 1))) * 4096 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(69, 1))) * 256 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(70, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(71, 1))) * 1
				)).c_str());

		CString Line4DestinationPort = CString(std::to_string(
			(_ttoi(HexToDec(Packet_Dump_Data.Mid(72, 1))) * 4096 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(73, 1))) * 256 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(74, 1))) * 16 +
				_ttoi(HexToDec(Packet_Dump_Data.Mid(75, 1))) * 1
				)).c_str());

		// Line 1
		HTREEITEM  PacketDataRoot1 = PacketDataCtrl.InsertItem(PacketDataLine1);
		HTREEITEM  PacketDataRoot1Child1 = PacketDataCtrl.InsertItem(PakcetDataLine1by1, PacketDataRoot1);
		HTREEITEM  PacketDataRoot1Child1Child1 = PacketDataCtrl.InsertItem(PakcetDataLine1by1by1, PacketDataRoot1Child1);
		HTREEITEM  PacketDataRoot1Child1Child2 = PacketDataCtrl.InsertItem(PakcetDataLine1by1by2, PacketDataRoot1Child1);

		HTREEITEM  PacketDataRoot1Child2 = PacketDataCtrl.InsertItem(PakcetDataLine1by2, PacketDataRoot1);
		HTREEITEM  PacketDataRoot1Child3 = PacketDataCtrl.InsertItem(PakcetDataLine1by3, PacketDataRoot1);
		HTREEITEM  PacketDataRoot1Child4 = PacketDataCtrl.InsertItem(PakcetDataLine1by4, PacketDataRoot1);
		HTREEITEM  PacketDataRoot1Child5 = PacketDataCtrl.InsertItem(PakcetDataLine1by5, PacketDataRoot1);
		HTREEITEM  PacketDataRoot1Child6 = PacketDataCtrl.InsertItem(PakcetDataLine1by6, PacketDataRoot1);


		// Line 2
		HTREEITEM  PacketDataRoot2 = PacketDataCtrl.InsertItem(PacketDataLine2);
		HTREEITEM  PacketDataRoot2Child1 = PacketDataCtrl.InsertItem(PakcetDataLine2by1, PacketDataRoot2);
		HTREEITEM  PacketDataRoot2Child2 = PacketDataCtrl.InsertItem(PakcetDataLine2by2, PacketDataRoot2);
		HTREEITEM  PacketDataRoot2Child3 = PacketDataCtrl.InsertItem(PakcetDataLine2by3, PacketDataRoot2);
		if (Length == L"60") {
			HTREEITEM  PacketDataRoot2Child4 = PacketDataCtrl.InsertItem(PakcetDataLine2by4, PacketDataRoot2);
		}


		// Line 3
		HTREEITEM  PacketDataRoot3 = PacketDataCtrl.InsertItem(PacketDataLine3);
		HTREEITEM  PacketDataRoot3Child1 = PacketDataCtrl.InsertItem(PacketDataLine3by1, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child2 = PacketDataCtrl.InsertItem(PacketDataLine3by2, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child3 = PacketDataCtrl.InsertItem(PacketDataLine3by3, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child4 = PacketDataCtrl.InsertItem(PacketDataLine3by4, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child5 = PacketDataCtrl.InsertItem(PacketDataLine3by5, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child6 = PacketDataCtrl.InsertItem(PacketDataLine3by6, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child7 = PacketDataCtrl.InsertItem(PacketDataLine3by7, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child8 = PacketDataCtrl.InsertItem(PacketDataLine3by8, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child9 = PacketDataCtrl.InsertItem(PacketDataLine3by9, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child10 = PacketDataCtrl.InsertItem(PacketDataLine3by10, PacketDataRoot3);
		HTREEITEM  PacketDataRoot3Child11 = PacketDataCtrl.InsertItem(PacketDataLine3by11, PacketDataRoot3);


		//=======================================
		if (Protocol == L"TCP") {
			/*
			Frame 123: 60 bytes on wire (480bits), 60 bytes captured (480 bits) on interface 0
			Ethernet II, Src: FF:FF:FF:FF:FF:FF, Dst: 00:00:00:00:00:00
			Internet Protocol Version 4, Src: 192.168.0.1, Dst: 127.0.0.1
			Transmission Control Protocol, Src Port: 9999, Dst Port: 666, Seq: 64, Ack: 1, Len: 0
			*/
			


			PacketDataLine4 = L"Transmission Control Protocol, Src Port: " + Line4SourcePort + L", Dst Port: " + Line4DestinationPort;
			CString PacketDataLine4by1 = L"Source Port: " + Line4SourcePort;
			CString PacketDataLine4by2 = L"Destination Port: " + Line4DestinationPort;
			CString PacketDataLine4by3 = L"Sequence number: " + Packet_Dump_Data.Mid(76, 8);
			CString PacketDataLine4by4 = L"Acknowledge number: " + Packet_Dump_Data.Mid(84, 8);
			CString PacketDataLine4by5 = HexToBinary(HexToDec(Packet_Dump_Data.Mid(92,1))) + L" . . . . = Header Length: " 
				+ CString(std::to_string(_ttoi(Packet_Dump_Data.Mid(92, 1))*4).c_str()) + " bytes ("
				+ CString(std::to_string(_ttoi(Packet_Dump_Data.Mid(92, 1))).c_str())+")";
			

			// Reserver+Flag;
			// 6bits -> Reserved
			CString BinaryTCPFlag = GetTCPFlagToBin(Packet_Dump_Data.Mid(93, 3));

			CString Reserved = BinaryTCPFlag.Mid(0, 3);
			CString Nonce = BinaryTCPFlag.Mid(3, 1);
			CString CongestionWindowReduced = BinaryTCPFlag.Mid(4, 1);
			CString ECN_Echo = BinaryTCPFlag.Mid(5, 1);

			// Flag
			// 6bits -> Flags
			CString Urgent = BinaryTCPFlag.Mid(6, 1);
			CString Acknowledgment = BinaryTCPFlag.Mid(7, 1);
			CString Push = BinaryTCPFlag.Mid(8, 1);
			CString Reset = BinaryTCPFlag.Mid(9, 1);
			CString Syn = BinaryTCPFlag.Mid(10, 1);
			CString Fin = BinaryTCPFlag.Mid(11, 1);

			// Only Binary Flag;
			CString TCPFlagBinaryOnly;

			for (int i = 6; i < 12; i++) {
				TCPFlagBinaryOnly.Append(BinaryTCPFlag.Mid(i, 1));
			}


			// TCP Flags:  . . . . . . .A . . .F 의 형식
			CString TCPFlagLongStr = GetTCPFlagToLongStr(BinaryTCPFlag);

			CString PacketDataLine4by6 = L"Flags: 0x" + Packet_Dump_Data.Mid(93, 3) + L"(" + GetTCPFlagToStr(TCPFlagBinaryOnly) + L")";

			CString PacketDataLine4by6by1 = Reserved;
			CString PacketDataLine4by6by2 = Nonce;
			CString PacketDataLine4by6by3 = CongestionWindowReduced;
			CString PacketDataLine4by6by4 = ECN_Echo;
			CString PacketDataLine4by6by5 = Urgent;
			CString PacketDataLine4by6by6 = Acknowledgment;
			CString PacketDataLine4by6by7 = Push;
			CString PacketDataLine4by6by8 = Reset;
			CString PacketDataLine4by6by9 = Syn;
			CString PacketDataLine4by6by10 = Fin;
			CString PacketDataLine4by6by11 = L"[TCP Flags: " + TCPFlagLongStr+"]";


			// Reserved
			if (PacketDataLine4by6by1 != L"000") {
				PacketDataLine4by6by1 = Reserved + L".  . . . .  . . . . = Reserved: Set";
			}
			else {
				PacketDataLine4by6by1 = Reserved + L".  . . . .  . . . . = Reserved: Not set";
			}

			// Nonce
			if (PacketDataLine4by6by2 != L"0") {
				PacketDataLine4by6by2 = L". . ." + Nonce + L"  . . . .  . . . . = Nonce: Set";
			}
			else {
				PacketDataLine4by6by2 = L". . ." + Nonce + L"  . . . .  . . . . = Nonce: Noe set";
			}

			// CongestionWindowReduced
			if (PacketDataLine4by6by3 != L"0") {
				PacketDataLine4by6by3 = L". . . .  " + CongestionWindowReduced + L". . .  . . . . = CongestionWindowReduced (CWR) : Set";
			}
			else {
				PacketDataLine4by6by3 = L". . . .  " + CongestionWindowReduced + L". . .  . . . . = CongestionWindowReduced (CWR) : Not set";
			}

			// ECN_Echo
			if (PacketDataLine4by6by4 != L"0") {
				PacketDataLine4by6by4 = L". . . .  . " + ECN_Echo + L". .  . . . . = ECN-Echo : Set";
			}
			else {
				PacketDataLine4by6by4 = L". . . .  . " + ECN_Echo + L". .  . . . . = ECN-Echo : Not set";
			}

			// Urgent
			if (PacketDataLine4by6by5 != L"0") {
				PacketDataLine4by6by5 = L". . . .  . . " + Urgent + L".  . . . . = Urgent : Set";
			}
			else {
				PacketDataLine4by6by5 = L". . . .  . . " + Urgent + L".  . . . . = Urgent : Not set";
			}

			// Acknowledgment
			if (PacketDataLine4by6by6 != L"0") {
				PacketDataLine4by6by6 = L". . . .  . . ." + Acknowledgment + L"  . . . . = Acknowledgment : Set";
			}
			else {
				PacketDataLine4by6by6 = L". . . .  . . ." + Acknowledgment + L"  . . . . = Acknowledgment : Not set";
			}

			// Push
			if (PacketDataLine4by6by7 != L"0") {
				PacketDataLine4by6by7 = L". . . .  . . . .  " + Push + L". . . = Push : Set";
			}
			else {
				PacketDataLine4by6by7 = L". . . .  . . . .  " + Push + L". . . = Push : Not set";
			}

			// Reset
			if (PacketDataLine4by6by8 != L"0") {
				PacketDataLine4by6by8 = L". . . .  . . . .  . " + Reset + L". . = Reset : Set";
			}
			else {
				PacketDataLine4by6by8 = L". . . .  . . . .  . " + Reset + L". . = Reset : Not set";
			}

			// Syn
			if (PacketDataLine4by6by9 != L"0") {
				PacketDataLine4by6by9 = L". . . .  . . . .  . . " + Syn + L". = Syn : Set";
			}
			else {
				PacketDataLine4by6by9 = L". . . .  . . . .  . . " + Syn + L". = Syn : Not set";
			}

			// Fin
			if (PacketDataLine4by6by10 != L"0") {
				PacketDataLine4by6by10 = L". . . .  . . . .  . . . " + Fin + L" = Fin : Set";
			}
			else {
				PacketDataLine4by6by10 = L". . . .  . . . .  . . ." + Fin + L" = Fin : Not set";
			}

			CString windowSize = CString(std::to_string(
				(_ttoi(HexToDec(Packet_Dump_Data.Mid(96, 1))) * 4096 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(97, 1))) * 256 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(98, 1))) * 16 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(99, 1))) * 1
					)).c_str());

			CString PacketDataLine4by7 = L"Window size value: " + windowSize;
			CString PacketDataLine4by8 = L"[Calculated window size: " + windowSize + L"]";
			CString PacketDataLine4by9 = L"Checksum: 0x"+ Packet_Dump_Data.Mid(100, 4);

			CString urgentPointer = CString(std::to_string(
				(_ttoi(HexToDec(Packet_Dump_Data.Mid(104, 1))) * 4096 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(105, 1))) * 256 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(106, 1))) * 16 +
					_ttoi(HexToDec(Packet_Dump_Data.Mid(107, 1))) * 1
					)).c_str());

			CString PacketDataLine4by10 = L"Urgent pointer: " + urgentPointer;




			

			// Line 4
			HTREEITEM  PacketDataRoot4 = PacketDataCtrl.InsertItem(PacketDataLine4);
			HTREEITEM  PacketDataRoot4Child1 = PacketDataCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child2 = PacketDataCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child3 = PacketDataCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child4 = PacketDataCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child5 = PacketDataCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child6 = PacketDataCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child6Child1 = PacketDataCtrl.InsertItem(PacketDataLine4by6by1, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child2 = PacketDataCtrl.InsertItem(PacketDataLine4by6by2, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child3 = PacketDataCtrl.InsertItem(PacketDataLine4by6by3, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child4 = PacketDataCtrl.InsertItem(PacketDataLine4by6by4, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child5 = PacketDataCtrl.InsertItem(PacketDataLine4by6by5, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child6 = PacketDataCtrl.InsertItem(PacketDataLine4by6by6, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child7 = PacketDataCtrl.InsertItem(PacketDataLine4by6by7, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child8 = PacketDataCtrl.InsertItem(PacketDataLine4by6by8, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child9 = PacketDataCtrl.InsertItem(PacketDataLine4by6by9, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child10 = PacketDataCtrl.InsertItem(PacketDataLine4by6by10, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child6Child11 = PacketDataCtrl.InsertItem(PacketDataLine4by6by11, PacketDataRoot4Child6);
			HTREEITEM  PacketDataRoot4Child7 = PacketDataCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child8 = PacketDataCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child9 = PacketDataCtrl.InsertItem(PacketDataLine4by9, PacketDataRoot4);
			HTREEITEM  PacketDataRoot4Child10 = PacketDataCtrl.InsertItem(PacketDataLine4by10, PacketDataRoot4);

			PacketDataCtrl.Expand(PacketDataRoot4, TVE_EXPAND);
		}else if (Protocol == L"UDP") {

		}
		else if (Protocol == L"ARP") {
			//Frame, Ethernet 으로 되어있음

		}
		else if (Protocol == L"ICMP") {

		}


		PacketDataCtrl.Expand(PacketDataRoot1, TVE_EXPAND);
		PacketDataCtrl.Expand(PacketDataRoot2, TVE_EXPAND);
		PacketDataCtrl.Expand(PacketDataRoot3, TVE_EXPAND);


		PacketDataCtrl.Invalidate();
		PacketDataCtrl.UpdateWindow();
	}


	PacketDumpList.DeleteAllItems();
	CString Packet_dump_data = m_ListCtrl.GetItemText(pNMItemActivate->iItem, 7);

	if (Packet_dump_data != L"") {
		for (int i = 0; i < Packet_dump_data.GetLength() + 1; i += 32) {
			int column_count = PacketDumpList.GetItemCount();
			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);

			std::stringstream stream;
			stream << std::setw(6) << std::setfill('0') << std::hex << (i / 2);

			std::string seq_number_str = stream.str();
			LPCSTR lpcstrSeqNum = (LPCSTR)seq_number_str.c_str();
			USES_CONVERSION;
			CString CstrSeqNum = A2CT(lpcstrSeqNum);
			CstrSeqNum.MakeUpper();
			PacketDumpList.InsertItem(column_count, CstrSeqNum);

			CString allHex = Packet_dump_data.Mid(i, 32);
			CString AsciiAllHex = allHex;
			allHex = allHex.MakeUpper();

			CString hex1, hex2;

			for (int i = 0; i < 16; i += 2) {
				hex1 += allHex.Mid(i, 2) + L"  ";
			}

			for (int i = 16; i < 32; i += 2) {
				hex2 += allHex.Mid(i, 2) + L"  ";
			}

			PacketDumpList.SetItem(column_count, 1, LVIF_TEXT, hex1, NULL, NULL, NULL, NULL);
			PacketDumpList.SetItem(column_count, 2, LVIF_TEXT, hex2, NULL, NULL, NULL, NULL);

			CString convAscii;
			CString PacketAscii1;
			CString PacketAscii2;

			for (int i = 0; i < AsciiAllHex.GetLength(); i += 2) {
				PacketAscii1 = AsciiAllHex.Mid(i, 1);
				PacketAscii2 = AsciiAllHex.Mid(i + 1, 1);

				if (PacketAscii1 == L"a") {
					PacketAscii1 = L"10";
				}
				if (PacketAscii1 == L"b") {
					PacketAscii1 = L"11";
				}
				if (PacketAscii1 == L"c") {
					PacketAscii1 = L"12";
				}
				if (PacketAscii1 == L"d") {
					PacketAscii1 = L"13";
				}
				if (PacketAscii1 == L"e") {
					PacketAscii1 = L"14";
				}
				if (PacketAscii1 == L"f") {
					PacketAscii1 = L"15";
				}

				if (PacketAscii2 == L"a") {
					PacketAscii2 = L"10";
				}
				if (PacketAscii2 == L"b") {
					PacketAscii2 = L"11";
				}
				if (PacketAscii2 == L"c") {
					PacketAscii2 = L"12";
				}
				if (PacketAscii2 == L"d") {
					PacketAscii2 = L"13";
				}
				if (PacketAscii2 == L"e") {
					PacketAscii2 = L"14";
				}
				if (PacketAscii2 == L"f") {
					PacketAscii2 = L"15";
				}

				int ten = _ttoi(PacketAscii1) * 16;
				int one = _ttoi(PacketAscii2);

				int sum = ten + one;
				ten = 0;
				one = 0;

				if (sum < 32 || sum>126) {
					sum = 46;
				}

				char ascii[4];
				ascii[0] = (char)sum;
				if (sum == 46) {
					sprintf(ascii, "%2c", ascii[0]);
				}
				else {
					sprintf(ascii, "%c", ascii[0]);
				}
				convAscii += ascii;
			}

			PacketDumpList.SetItem(column_count, 3, LVIF_TEXT, convAscii, NULL, NULL, NULL, NULL);
		}
	}
}

void CMFCApplication1Dlg::OnHdnItemclick(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMHEADER pNMLV = reinterpret_cast<LPNMHEADER>(pNMHDR);

	int nColumn = pNMLV->iItem;
	// 선택된 헤더 숫자로 정렬해야되는 값은 0번 (No)와 5번 (Length)이다.

	for (int i = 0; i < (m_ListCtrl.GetItemCount()); i++) {
		m_ListCtrl.SetItemData(i, i);
	}

	if (m_bAscending) {
		m_bAscending = false;
	}
	else {
		m_bAscending = true;
	}

	SORTPARAM sortparams;
	sortparams.pList = &m_ListCtrl;
	sortparams.iSrotColumn = nColumn;
	sortparams.bSortDirect = m_bAscending;

	if (nColumn == 0 || nColumn == 5) {
		m_ListCtrl.SortItems(&SortFuncNum, (LPARAM)& sortparams);
	}else {
		m_ListCtrl.SortItems(&SortFuncStr, (LPARAM)& sortparams);
	}

	*pResult = 0;
}


int CALLBACK CMFCApplication1Dlg::SortFuncStr(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	CListCtrl* pList = ((SORTPARAM*)lParamSort)->pList;
	int iSortColumn = ((SORTPARAM*)lParamSort)->iSrotColumn;
	bool bSortDirect = ((SORTPARAM*)lParamSort)->bSortDirect;


	LVFINDINFO info1, info2;
	info1.flags = LVFI_PARAM;
	info1.lParam = lParam1;
	info2.flags = LVFI_PARAM;
	info2.lParam = lParam2;

	int irow1 = pList->FindItem(&info1, -1);
	int irow2 = pList->FindItem(&info2, -1);

	CString strItem1 = pList->GetItemText(irow1, iSortColumn);
	CString strItem2 = pList->GetItemText(irow2, iSortColumn);

	return bSortDirect ? strItem1.Compare(strItem2) : -strItem1.Compare(strItem2);
}

int CALLBACK CMFCApplication1Dlg::SortFuncNum(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	CListCtrl* pList = ((SORTPARAM*)lParamSort)->pList;
	int iSortColumn = ((SORTPARAM*)lParamSort)->iSrotColumn;
	bool bSortDirect = ((SORTPARAM*)lParamSort)->bSortDirect;


	LVFINDINFO info1, info2;
	info1.flags = LVFI_PARAM;
	info1.lParam = lParam1;
	info2.flags = LVFI_PARAM;
	info2.lParam = lParam2;

	int irow1 = pList->FindItem(&info1, -1);
	int irow2 = pList->FindItem(&info2, -1);

	int numItem1 = _ttoi(pList->GetItemText(irow1, iSortColumn));
	int numItem2 = _ttoi(pList->GetItemText(irow2, iSortColumn));

	return !bSortDirect ? numItem1 < numItem2 : numItem1 > numItem2;
}

BOOL CMFCApplication1Dlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.

	if (pMsg->message == WM_KEYDOWN)
	{
		if (pMsg->wParam == VK_ESCAPE)
			return TRUE;
		else if (pMsg->wParam == VK_RETURN)
			return TRUE;
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}

CString CMFCApplication1Dlg::HexToDec(CString _number) {
	if (_number == L"a" || _number == L"A") {
		_number = L"10";
	}else 	if (_number == L"b" || _number == L"B") {
		_number = L"11";
	}else 	if (_number == L"c" || _number == L"C") {
		_number = L"12";
	}else 	if (_number == L"d" || _number == L"D") {
		_number = L"13";
	}else 	if (_number == L"e" || _number == L"E") {
		_number = L"14";
	}else 	if (_number == L"f" || _number == L"F") {
		_number = L"15";
	}
	else {
		_number = _number;
	}

	return _number;
}

CString CMFCApplication1Dlg::HexToBinary(CString _number) {
	CString result;
	CString temp1;
	CString temp2;
	CString temp3;
	CString temp4;

	temp1 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp2 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	_number = CString((std::to_string(_ttoi(_number) / 2)).c_str());
	temp3 = CString((std::to_string(_ttoi(_number) % 2)).c_str());
	temp4 = CString((std::to_string(_ttoi(_number) / 2)).c_str());

	result = temp4 + temp3 + temp2 + temp1;

	return result;
}

CString CMFCApplication1Dlg::GetTCPFlagToBin(CString _Flag) {
	// 6비트 예약 6비트 TCP 플래그
	/*
	1. Urgent 
	2. Acknowledge
	3. Push
	4. Reset
	5. Syn
	6. Fin
	*/
	CString Result;
	CString FirstByte = _Flag.Mid(0, 1);
	CString SecondByte = _Flag.Mid(1, 1);
	CString ThirdByte = _Flag.Mid(2, 1);

	FirstByte = HexToDec(FirstByte);
	SecondByte = HexToDec(SecondByte);
	ThirdByte = HexToDec(ThirdByte);

	FirstByte = HexToBinary(FirstByte);
	SecondByte = HexToBinary(SecondByte);
	ThirdByte = HexToBinary(ThirdByte);

	Result = FirstByte + SecondByte + ThirdByte;

	return Result;
}

CString CMFCApplication1Dlg::GetTCPFlagToStr(CString _Flag) {
	// 6비트 예약 6비트 TCP 플래그
	/*
	1. Urgent
	2. Acknowledge
	3. Push
	4. Reset
	5. Syn
	6. Fin
	*/
	CString Result;

	CString Urgent = _Flag.Mid(0, 1);
	CString Acknowledgment = _Flag.Mid(0, 1);
	CString Push= _Flag.Mid(0, 1);
	CString Reset = _Flag.Mid(0, 1);
	CString Syn = _Flag.Mid(0, 1);
	CString Fin = _Flag.Mid(0, 1);

	if (Urgent == L"1") {
		Result = "URG";
	}
	else if(Acknowledgment = L"1") {
		if (Result.IsEmpty() == true) {
			Result = "ACK";
		}
		else {
			Result.Append(L", ACK");
		}
	}
	else if (Push = L"1") {
		if (Result.IsEmpty() == true) {
			Result = "PUSH";
		}
		else {
			Result.Append(L", PUSH");
		}
	}
	else if (Reset = L"1") {
		if (Result.IsEmpty() == true) {
			Result = "RST";
		}
		else {
			Result.Append(L", RST");
		}
	}
	else if (Syn = L"1") {
		if (Result.IsEmpty() == true) {
			Result = "SYN";
		}
		else {
			Result.Append(L", SYN");
		}
	}
	else if (Fin = L"1") {
		if (Result.IsEmpty() == true) {
			Result = "FIN";
		}
		else {
			Result.Append(L", FIN");
		}
	}

	return Result;
}


CString CMFCApplication1Dlg::GetTCPFlagToLongStr(CString _Flag) {
	// 6비트 예약 6비트 TCP 플래그
	/*
	1. Urgent
	2. Acknowledge
	3. Push
	4. Reset
	5. Syn
	6. Fin
	*/
	CString Result = L"";
	CString FlagArray[6] = { L"U",L"A",L"P",L"R",L"S",L"F" };

	for (int i = 0; i < _Flag.GetLength(); i++) {
		if (_Flag.Mid(i, 1) == L"1"&&i>5) {
			Result.Append(FlagArray[i-6]);
		}
		else {
			Result.Append(L". ");
		}
	}

	return Result;
}