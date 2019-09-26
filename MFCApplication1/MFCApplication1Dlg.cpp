
// MFCApplication1Dlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"
#include "Resource.h"

#include "new_dialog.h"

#include <thread>
#include <sstream>

#include <pcap.h>
#include <afxconv.h>




#include "test.cpp"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif




int packet_cnt = 0;
int tcp_pkt_cnt = 0;
int udp_pkt_cnt = 0;
int arp_pkt_cnt = 0;
int icmp_pkt_cnt = 0;


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
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_ListCtrl);
	//  DDX_Control(pDX, IDC_BUTTON3, puase_button);
	DDX_Control(pDX, IDC_BUTTON3, pause_button);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication1Dlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication1Dlg::OnBnClickedButton3)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, OnCustomdrawList)
	// 2번째 인자 : List Control ID, 3번째 인자 : 실행할 함수
END_MESSAGE_MAP()


// CMFCApplication1Dlg 메시지 처리기

BOOL CMFCApplication1Dlg::OnInitDialog()
{
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

	SetWindowText(_T("Wire Dolphin"));
	packet_sniff::config::PacketSniff* pktSniff = (packet_sniff::config::PacketSniff*)malloc(sizeof(packet_sniff::config::PacketSniff));
	int error = pktSniff->find_all_network_interface();
	int network_interface_count = 0;

	CRect rt;
	m_ListCtrl.GetWindowRect(&rt);
	m_ListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	LV_COLUMN add_column;
	// 컬럼 속성을 지정한다. 텍스트 형식을 사용하고 폭을 명시하겠다고 설정한다.

	add_column.mask = LVCF_TEXT | LVCF_WIDTH;

	LPWSTR column_name[8] = { L"No",L"Time", L"Source", L"Destination", L"Protocol", L"Length", L"Info" };
	int count = 0;
	double column_width[8] = { 0.1,0.1,0.15,0.15,0.075,0.075,0.349 };

	for (int i = 0; i < 7; i++) {
		add_column.pszText = column_name[i];
		add_column.cx = rt.Width() * column_width[i];
		m_ListCtrl.InsertColumn(i, &add_column);
	}

	int column_count = m_ListCtrl.GetItemCount();


	// 패킷의 갯수 카운트
	ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
	
	
	/* 네트워크 다바이스명을 출력한다. */
	for (pktSniff->target_network_interface = pktSniff->all_network_interfaces; pktSniff->target_network_interface; pktSniff->target_network_interface = pktSniff->target_network_interface->next){
		printf("%d. %s", ++network_interface_count, pktSniff->target_network_interface->name);
		if (pktSniff->target_network_interface->description)
			printf(" (%s)\n", pktSniff->target_network_interface->description);
		else
			printf(" (No description available)\n");

		//m_ListCtrl.InsertItem(column_count,/* (CString)pktSniff->target_network_interface->description + " " + */(CString)pktSniff->target_network_interface->name);
	}

	/* 에러 처리 */
	if (network_interface_count == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}


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
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	const char* filter = "arp or tcp or udp or icmp";
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
	inum = 7;

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

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char *pkt_data) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	int i;
	ip_header* ih;
	udp_header* uh;
	tcp_header* th;
	icmp_header* icmp_hdr;
	u_int ip_len;

	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);


	ih = (ip_header*)(pkt_data + 14);
	ip_len = (ih->ver_ihl & 0xf) * 4;

	int size = sizeof(pkt_data);

	if (ih->proto == IPPROTO_TCP){
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
			+" -> "+
			(CString)(std::to_string(ntohs(th->dport)).c_str())
			, NULL, NULL, NULL, NULL);

		++tcp_pkt_cnt;
		++packet_cnt;

		pDlg->ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
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

		++udp_pkt_cnt;
		++packet_cnt;
		pDlg->ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
	}
	else if (ih->proto == 156) {
		// ARP


		++arp_pkt_cnt;
		++packet_cnt;
		pDlg->ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
	}
	else if (ih->proto == 1) {
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


		++icmp_pkt_cnt;
		++packet_cnt;
		pDlg->ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
	}else {
		printf("Unknown Protocol\n");
	}

	pDlg->ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);

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
			pause_button.SetWindowText(L"재개");
			m_pThread->SuspendThread();
			m_ThreadWorkType = PAUSE;
		}
		else {
			pause_button.SetWindowText(L"일시정지");
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
	strftime(buff, 1024, "%Y년%m월%d일-%H시%M분%S초 %p", st_time);

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
			pLVCD->clrTextBk = RGB(218, 238, 255); // 배경 색 변경 
		}
		else if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"UDP") {
			pLVCD->clrTextBk = RGB(231, 230, 255);
		}
		else if (m_ListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4) == L"ICMP") {
			pLVCD->clrTextBk = RGB(252, 224, 255);
		}

		*pResult = CDRF_DODEFAULT;
	}
}