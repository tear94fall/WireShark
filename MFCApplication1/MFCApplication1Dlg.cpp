
// MFCApplication1Dlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"
#include "Resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.
class CAboutDlg : public CDialogEx {
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

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX) {
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 대화 상자



CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent) {
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_PacketCapturedListCtrl);
	DDX_Control(pDX, IDC_BUTTON3, pause_button);
	DDX_Control(pDX, IDC_TREE1, m_PacketDataTreeCtrl);
	DDX_Control(pDX, IDC_LIST1, m_PacketDumpListCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_FilterEditCtrl);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnBnClickedCaptureStartButton)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication1Dlg::OnBnClickedCaptureQuitButton)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication1Dlg::OnBnClickedCapturePauseButton)
	ON_BN_CLICKED(IDC_BUTTON4, &CMFCApplication1Dlg::OnBnClickedFilterApplyButton)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, &CMFCApplication1Dlg::OnCustomdrawList)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST2, &CMFCApplication1Dlg::OnNMDblclkList2)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &CMFCApplication1Dlg::OnHdnItemclick)
	ON_COMMAND(ID_FILE_1, &CMFCApplication1Dlg::OpenPacketDataFile)
	ON_COMMAND(ID_1_1, &CMFCApplication1Dlg::FileSave)
	//	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CMFCApplication1Dlg::OnNMCustomdrawList1)
	//	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CMFCApplication1Dlg::OnLvnItemchangedList1)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CMFCApplication1Dlg 메시지 처리기

BOOL CMFCApplication1Dlg::OnInitDialog() {
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
	if (pSysMenu != nullptr) {
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty()) {
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	std::remove(file_name_write);

	SetWindowText(_T("Wire Dolphin"));

	// File 체크 비활성
	GetDlgItem(IDC_CHECK2)->EnableWindow(FALSE);

	m_strSelectedNetworkInterface = netInterfaceDlg.InterfaceDescription;
	SetDlgItemText(IDC_STATIC_NET, L"Interface: " + m_strSelectedNetworkInterface);

	CButton* pButton = (CButton*)GetDlgItem(IDC_BUTTON2);
	pButton->EnableWindow(FALSE);

	CButton* pButton3 = (CButton*)GetDlgItem(IDC_BUTTON3);
	pButton3->EnableWindow(FALSE);

	m_FilterEditCtrl.SetWindowTextW(DefaultFilterValue);

	CRect rectangle;
	m_PacketCapturedListCtrl.GetWindowRect(&rectangle);
	m_PacketCapturedListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	LV_COLUMN add_column;

	// 컬럼 속성을 지정한다. 텍스트 형식을 사용하고 폭을 명시하겠다고 설정한다.
	add_column.mask = LVCF_TEXT | LVCF_WIDTH;

	const int packet_list_column_count = 9;
	LPWSTR column_name[packet_list_column_count] = { L"No",L"Time", L"Source", L"Destination", L"Protocol", L"Length", L"Info" ,L"Dump Data" };
	double column_width[packet_list_column_count] = { 0.1, 0.17, 0.15, 0.15, 0.075, 0.075, 0.25, 0 };

	for (int i = 0; i < packet_list_column_count - 1; i++) {
		add_column.pszText = column_name[i];
		add_column.cx = (double)rectangle.Width() * column_width[i];
		m_PacketCapturedListCtrl.InsertColumn(i, &add_column);
	}

	m_PacketDumpListCtrl.GetWindowRect(&rectangle);
	m_PacketDumpListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	const int packet_dump_column_count = 4;
	LPWSTR packet_dump_header[packet_dump_column_count] = { L"Seq",L"Hex 1",L"HEX 2", L"ASCII" };
	double pakcet_dump_header_width[packet_dump_column_count] = { 0.1,0.27,0.27,0.3 };

	for (int i = 0; i < packet_dump_column_count; i++) {
		add_column.pszText = packet_dump_header[i];
		add_column.cx = rectangle.Width() * pakcet_dump_header_width[i];
		m_PacketDumpListCtrl.InsertColumn(i, &add_column);
	}

	ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void CMFCApplication1Dlg::OnSysCommand(UINT nID, LPARAM lParam) {
	if ((nID & 0xFFF0) == IDM_ABOUTBOX) {
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	} else {
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CMFCApplication1Dlg::OnPaint() {
	if (IsIconic()) {
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
	} else {
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon() {
	return static_cast<HCURSOR>(m_hIcon);
}


void CMFCApplication1Dlg::OnBnClickedCaptureStartButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	SetDlgItemText(IDC_STATIC_NET, L"Interface: " + m_strSelectedNetworkInterface);

	IsFilterApply = FALSE;

	if (m_PacketCaptrueThread == NULL) {
		ClearPacketCnt();
		m_PacketCapturedListCtrl.DeleteAllItems();

		std::ofstream out(file_name_write, std::ios::trunc);
		m_PacketCaptrueThread = AfxBeginThread(PacketCaptureThreadFunction, this);
		CButton* pButton;
		pButton = (CButton*)GetDlgItem(IDC_BUTTON1);
		pButton->EnableWindow(FALSE);

		pButton = (CButton*)GetDlgItem(IDC_BUTTON2);
		pButton->EnableWindow(TRUE);

		pButton = (CButton*)GetDlgItem(IDC_BUTTON3);
		pButton->EnableWindow(TRUE);

		if (m_PacketCaptrueThread == NULL) {
			AfxMessageBox(_T("캡처 시작을 할 수 없습니다."));
		}

		if (m_PacketCaptrueThread != NULL) {
			m_PacketCaptrueThread->m_bAutoDelete = FALSE;
		}
		m_PacketCaptureThreadWorkType = RUNNING;
	} else {
		if (m_PacketCaptureThreadWorkType == RUNNING || m_PacketCaptureThreadWorkType == PAUSE) {
		}
	}
}


UINT CMFCApplication1Dlg::PacketCaptureThreadFunction(LPVOID _mothod) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	pcap_if_t* all_net_device;
	pcap_if_t* net_device = NULL;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	const char* filter = "tcp or udp or arp or icmp";
	struct bpf_program fcode;
	bpf_u_int32 NetMask;

	if (pcap_findalldevs(&all_net_device, errbuf) == -1) {
		AfxMessageBox(CString(errbuf));
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (net_device = all_net_device; net_device; net_device = net_device->next) {
		++i;
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	inum = pDlg->netInterfaceDlg.m_nSelectedIndex + 1;

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(all_net_device);
		return -1;
	}

	for (net_device = all_net_device, i = 0; i < inum - 1; net_device = net_device->next, i++);

	if ((adhandle = pcap_open_live(net_device->name, 65536, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", net_device->name);
		pcap_freealldevs(all_net_device);
		return -1;
	}

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

	pcap_freealldevs(all_net_device);
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	pDlg->m_header = header;
	pDlg->m_pkt_data = pkt_data;
	pDlg->eth_hdr = (ether_header*)pkt_data;
	pDlg->ip_hdr = (ip_header*)(pkt_data + 14);
	pDlg->ip_len = (pDlg->ip_hdr->ver_ihl & 0xf) * 4;

	int size = sizeof(pkt_data);

	pDlg->CurrentTimeStr = CString(pDlg->GetCurrentTimeStr().c_str());
	pDlg->source_ip = pDlg->GetIPAddr(pDlg->ip_hdr->saddr);
	pDlg->destionation_ip = pDlg->GetIPAddr(pDlg->ip_hdr->daddr);
	pDlg->Protocol;
	pDlg->Length = (CString)(std::to_string(header->caplen).c_str());

	if (pDlg->CurrentTimeStr.IsEmpty() || pDlg->source_ip.IsEmpty() || pDlg->destionation_ip.IsEmpty() || pDlg->Length.IsEmpty()) {
		return;
	}

	std::string packet_dump_data_string;
	for (int i = 1; (i < header->caplen + 1); i++) {
		char* temp = NULL;

		int temp2 = pkt_data[i - 1];
		std::stringstream stream;
		stream << std::setw(2) << std::setfill('0') << std::hex << temp2;

		packet_dump_data_string += stream.str();
	}

	CString packet_dump_data_cstr(packet_dump_data_string.c_str());

	if (!pDlg->IsFilterApply) {
		if (ntohs(pDlg->eth_hdr->frame_type) == 0x0800) {
			if (pDlg->ip_hdr->proto == IPPROTO_TCP) {
				pDlg->Protocol = L"TCP";
				pDlg->tcp_hdr = (tcp_header*)((u_char*)pDlg->ip_hdr + pDlg->ip_len);

				int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

				CString column_count_str;
				column_count_str.Format(_T("%d"), column_count + 1);
				pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);

				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 1, LVIF_TEXT, pDlg->CurrentTimeStr, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 2, LVIF_TEXT, pDlg->source_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 3, LVIF_TEXT, pDlg->destionation_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 4, LVIF_TEXT, pDlg->Protocol, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 5, LVIF_TEXT, pDlg->Length, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(htons(pDlg->tcp_hdr->sport)).c_str()) + " -> " + (CString)(std::to_string(ntohs(pDlg->tcp_hdr->dport)).c_str()), NULL, NULL, NULL, NULL);

				++pDlg->tcp_pkt_cnt;
				++pDlg->packet_cnt;
			} else if (pDlg->ip_hdr->proto == 4) {
				printf("IP\n");
			} else if (pDlg->ip_hdr->proto == IPPROTO_UDP) {
				pDlg->Protocol = L"UDP";
				pDlg->udp_hdr = (udp_header*)((u_char*)pDlg->ip_hdr + pDlg->ip_len);

				int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

				CString column_count_str;
				column_count_str.Format(_T("%d"), column_count + 1);
				pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);

				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 1, LVIF_TEXT, pDlg->CurrentTimeStr, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 2, LVIF_TEXT, pDlg->source_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 3, LVIF_TEXT, pDlg->destionation_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 4, LVIF_TEXT, pDlg->Protocol, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 5, LVIF_TEXT, pDlg->Length, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(htons(pDlg->udp_hdr->sport)).c_str()) + " -> " + (CString)(std::to_string(ntohs(pDlg->udp_hdr->dport)).c_str()), NULL, NULL, NULL, NULL);

				++pDlg->udp_pkt_cnt;
				++pDlg->packet_cnt;
			} else if (pDlg->ip_hdr->proto == IPPROTO_ICMP) {
				pDlg->Protocol = L"ICMP";
				pDlg->icmp_hdr = (icmp_header*)(pDlg->ip_hdr + pDlg->ip_len);

				int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

				CString column_count_str;
				column_count_str.Format(_T("%d"), column_count + 1);
				pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);

				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 1, LVIF_TEXT, pDlg->CurrentTimeStr, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 2, LVIF_TEXT, pDlg->source_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 3, LVIF_TEXT, pDlg->destionation_ip, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 4, LVIF_TEXT, pDlg->Protocol, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 5, LVIF_TEXT, pDlg->Length, NULL, NULL, NULL, NULL);
				pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 6, LVIF_TEXT, (CString)(std::to_string(pDlg->icmp_hdr->code).c_str()), NULL, NULL, NULL, NULL);


				++pDlg->icmp_pkt_cnt;
				++pDlg->packet_cnt;
			} else {
				printf("Unknown Protocol\n");
				unsigned char temp = pDlg->ip_hdr->proto;

			}
		} else if (ntohs(pDlg->eth_hdr->frame_type) == 0x0806) {
			pDlg->Protocol = L"ARP";
			pDlg->arp_hdr = (struct arp_header*)(pkt_data + 14);

			int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);
			pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);

			char soure_hw_addr[4];
			char target_hw_addr[4];

			CString sender_hw_addr, target_hw_adr;
			for (int i = 0; i < 5; i++) {
				sprintf(soure_hw_addr, "%02x:", pDlg->arp_hdr->sha[i]);
				sender_hw_addr += soure_hw_addr;

				sprintf(target_hw_addr, "%02x:", pDlg->arp_hdr->tha[i]);
				target_hw_adr += target_hw_addr;
			}

			sprintf(soure_hw_addr, "%02x", pDlg->arp_hdr->sha[5]);
			sender_hw_addr += soure_hw_addr;

			sprintf(target_hw_addr, "%02x", pDlg->arp_hdr->tha[5]);
			target_hw_adr += target_hw_addr;


			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 1, LVIF_TEXT, pDlg->CurrentTimeStr, NULL, NULL, NULL, NULL);
			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 2, LVIF_TEXT, pDlg->source_ip, NULL, NULL, NULL, NULL);
			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 3, LVIF_TEXT, pDlg->destionation_ip, NULL, NULL, NULL, NULL);
			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 4, LVIF_TEXT, pDlg->Protocol, NULL, NULL, NULL, NULL);
			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 5, LVIF_TEXT, pDlg->Length, NULL, NULL, NULL, NULL);
			pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 6, LVIF_TEXT, sender_hw_addr + L" -> " + target_hw_adr, NULL, NULL, NULL, NULL);

			++pDlg->arp_pkt_cnt;
			++pDlg->packet_cnt;
		} else {
			return;
		}

		int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount() - 1;
		pDlg->m_PacketCapturedListCtrl.SetItem(column_count, 7, LVIF_TEXT, packet_dump_data_cstr, NULL, NULL, NULL, NULL);

		int nCount = pDlg->m_PacketCapturedListCtrl.GetItemCount();
		pDlg->m_PacketCapturedListCtrl.EnsureVisible(nCount - 1, FALSE);
	} else {
		if (ntohs(pDlg->eth_hdr->frame_type) == 0x0800 || ntohs(pDlg->eth_hdr->frame_type) == 0x0806) {
			pDlg->packet_cnt += 1;
			if (pDlg->ip_hdr->proto == IPPROTO_TCP) {
				pDlg->tcp_pkt_cnt++;
			} else if (pDlg->ip_hdr->proto == IPPROTO_UDP) {
				pDlg->udp_pkt_cnt++;
			} else if (pDlg->ip_hdr->proto == IPPROTO_ICMP) {
				pDlg->icmp_pkt_cnt++;
			} else if (ntohs(pDlg->eth_hdr->frame_type) == 0x0806) {
				pDlg->arp_pkt_cnt++;
			}
		}
	}

	if (pDlg->m_PacketCapturedListCtrl.GetItemCount() == 1) {
		CString column_count_str = L"1";
		pDlg->SetDataToPacketData(column_count_str, CString(pDlg->GetCurrentTimeStr().c_str()), pDlg->source_ip, pDlg->destionation_ip, pDlg->Protocol, (CString)(std::to_string(header->caplen).c_str()), NULL, packet_dump_data_cstr);
		pDlg->SetDataToHDXEditor(packet_dump_data_cstr);
	}

	pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);

	pDlg->FileWriterFunction(pDlg->file_name_write);
	
	if (pDlg->packet_cnt % pDlg->packet_count_per_file == 0) {
		CString file_name = L"temp (";
		CString file_ext = L").dat";
		int number = pDlg->packet_cnt / pDlg->packet_count_per_file;
		CString number_cstr = (CString)std::to_string(number).c_str();
		file_name.Append(number_cstr);
		file_name.Append(file_ext);
		pDlg->file_name_cstr = file_name;
		pDlg->m_PacketCapturedListCtrl.DeleteAllItems();
	}
}

void CMFCApplication1Dlg::FileWriterFunction(char* file_name) {
	if (ntohs(eth_hdr->frame_type) == 0x0806 || ntohs(eth_hdr->frame_type) == 0x0800) {
		unsigned char c;
		int packet_size = m_header->caplen;

		CT2CA ConvertCStringToString(file_name_cstr);
		std::string file_name_temp(ConvertCStringToString);

		std::ofstream out(file_name_temp.c_str(), std::ios::app);



		CT2CA pszConvertedAnsiString(GetIPAddr(ip_hdr->saddr));
		std::string s(pszConvertedAnsiString);
		std::string sip = s;

		CT2CA pszConvertedAnsiString2(GetIPAddr(ip_hdr->daddr));
		std::string s2(pszConvertedAnsiString2);
		std::string dip = s2;

		std::string protocol;
		if (ntohs(eth_hdr->frame_type) == 0x0800) {
			if (ip_hdr->proto == IPPROTO_TCP) {
				protocol = "TCP";
			} else if (ip_hdr->proto == IPPROTO_UDP) {
				protocol = "UDP";
			}if (ip_hdr->proto == IPPROTO_ICMP) {
				protocol = "ICMP";
			}
		} else if (ntohs(eth_hdr->frame_type) == 0x0806) {
			protocol = "ARP";
		}

		out << packet_cnt << "\n";
		out << GetCurrentTimeStr() << "\n";
		out << sip << " \n";
		out << dip << " \n";
		out << protocol << " \n";
		out << m_header->caplen << " \n";
		out << "Info" << " \n";

		for (int i = 0; i < packet_size; i++) {
			c = m_pkt_data[i];
			out.width(2);
			out << std::hex << std::setfill('0') << (unsigned int)m_pkt_data[i] << " ";

			if ((i != 0 && (i + 1) % 16 == 0) || i == packet_size - 1) {
				out << "\n";
			}
		}
		out << "END\n";

		out.close();
	}
}

void CMFCApplication1Dlg::OnBnClickedCaptureQuitButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	int answer = MessageBox(_T("캡처를 종료합니다."), _T("캡처 종료"), MB_YESNO | MB_ICONQUESTION);

	if (answer == IDYES) {	// 예
		if (m_PacketCaptrueThread == NULL) {

		} else {
			DWORD dwResult;

			m_PacketCaptrueThread->SuspendThread();
			m_PacketCaptureThreadWorkType = STOP;
			::GetExitCodeThread(m_PacketCaptrueThread->m_hThread, &dwResult);
			delete m_PacketCaptrueThread;
			m_PacketCaptrueThread = NULL;

			if (m_FileReadThread != NULL) {
				m_FileReadThread->SuspendThread();
				m_FileReadThreadWorkType = STOP;
				::GetExitCodeThread(m_FileReadThread->m_hThread, &dwResult);
				delete m_FileReadThread;
				m_FileReadThread = NULL;
			}

			if (m_FileOpenThread != NULL) {
				m_FileOpenThread->SuspendThread();
				m_FileOpenThreadWorkType = STOP;
				::GetExitCodeThread(m_FileOpenThread->m_hThread, &dwResult);
				delete m_FileOpenThread;
				m_FileOpenThread = NULL;
			}

			CButton* pButton;
			pButton = (CButton*)GetDlgItem(IDC_BUTTON1);
			pButton->EnableWindow(TRUE);
			pButton = (CButton*)GetDlgItem(IDC_BUTTON2);
			pButton->EnableWindow(FALSE);
			pButton = (CButton*)GetDlgItem(IDC_BUTTON3);
			pButton->EnableWindow(FALSE);

			ClearPacketCnt();
			ChangeStaticText(packet_cnt, tcp_pkt_cnt, udp_pkt_cnt, arp_pkt_cnt, icmp_pkt_cnt);
			m_PacketCapturedListCtrl.DeleteAllItems();
			m_PacketDataTreeCtrl.DeleteAllItems();
			m_PacketDumpListCtrl.DeleteAllItems();

			if (!is_file_save) {
				std::ifstream in(file_name_write, std::ios::out);
				std::string s;
				if (in.is_open()) {
					in >> s;
					std::remove(file_name_write);
				}
			}
			is_file_save = false;
			
			m_FilterEditCtrl.Clear();
			m_FilterEditCtrl.SetWindowTextW(DefaultFilterValue);
		}
	} else if (answer == IDNO) {	// 아니오
	}
}

void CMFCApplication1Dlg::ChangeStaticText(int all_pkt_cnt, int tcp_pkt_cnt, int udp_pkt_cnt, int arp_pkt_cnt, int icmp_pkt_cnt) {
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

void CMFCApplication1Dlg::OnBnClickedCapturePauseButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (m_PacketCaptrueThread == NULL) {
	} else {
		if (m_PacketCaptureThreadWorkType == RUNNING) {
			pause_button.SetWindowText(L"Resume");
			m_PacketCaptrueThread->SuspendThread();
			m_PacketCaptureThreadWorkType = PAUSE;
		} else {
			pause_button.SetWindowText(L"Pause");
			m_PacketCaptrueThread->ResumeThread();
			m_PacketCaptureThreadWorkType = RUNNING;
		}
	}
}


std::string CMFCApplication1Dlg::GetCurrentTimeStr() {
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
	} else if (CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage) {
		CString Protocl = m_PacketCapturedListCtrl.GetItemText(pLVCD->nmcd.dwItemSpec, 4);

		if (Protocl == L"TCP") {
			pLVCD->clrTextBk = RGB(231, 230, 255);
		} else if (Protocl == L"UDP") {
			pLVCD->clrTextBk = RGB(218, 238, 255);
		} else if (Protocl == L"ICMP") {
			pLVCD->clrTextBk = RGB(252, 224, 255);
		} else if (Protocl == L"ARP") {
			pLVCD->clrTextBk = RGB(250, 240, 215);
		}
		*pResult = CDRF_DODEFAULT;
	}
}

void CMFCApplication1Dlg::OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	*pResult = 0;

	if (pNMItemActivate->iItem != -1) {
		CString FrameNumber = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 0);
		CString Time = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 1);
		CString Source = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 2);
		CString Destination = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 3);
		CString Protocol = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 4);
		CString Length = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 5);
		CString Info = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 6);
		CString Packet_Dump_Data = m_PacketCapturedListCtrl.GetItemText(pNMItemActivate->iItem, 7);

		m_PacketDataTreeCtrl.DeleteAllItems();
		m_PacketDumpListCtrl.DeleteAllItems();

		SetDataToPacketData(FrameNumber, Time, Source, Destination, Protocol, Length, Info, Packet_Dump_Data);
		SetDataToHDXEditor(Packet_Dump_Data);
	}
}

void CMFCApplication1Dlg::OnHdnItemclick(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMHEADER pNMLV = reinterpret_cast<LPNMHEADER>(pNMHDR);

	int nColumn = pNMLV->iItem;
	// 선택된 헤더 숫자로 정렬해야되는 값은 0번 (No)와 5번 (Length)이다.

	for (int i = 0; i < (m_PacketCapturedListCtrl.GetItemCount()); i++) {
		m_PacketCapturedListCtrl.SetItemData(i, i);
	}

	if (m_bAscending) {
		m_bAscending = false;
	} else {
		m_bAscending = true;
	}

	SORTPARAM sortparams;
	sortparams.pList = &m_PacketCapturedListCtrl;
	sortparams.iSrotColumn = nColumn;
	sortparams.bSortDirect = m_bAscending;

	if (nColumn == 0 || nColumn == 5) {
		m_PacketCapturedListCtrl.SortItems(&SortFuncNum, (LPARAM)& sortparams);
	} else {
		m_PacketCapturedListCtrl.SortItems(&SortFuncStr, (LPARAM)& sortparams);
	}

	*pResult = 0;
}


int CALLBACK CMFCApplication1Dlg::SortFuncStr(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
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

int CALLBACK CMFCApplication1Dlg::SortFuncNum(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
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

BOOL CMFCApplication1Dlg::PreTranslateMessage(MSG* pMsg) {
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.

	if (pMsg->message == WM_KEYDOWN) {
		if (pMsg->wParam == VK_ESCAPE)
			return TRUE;
		else if (pMsg->wParam == VK_RETURN)
			return TRUE;
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}

CString CMFCApplication1Dlg::HexToDec(CString _number) {
	wchar_t* end = NULL;
	long value = wcstol(_number, &end, 16);

	CString decStr;
	decStr.Format(L"%d", value);

	return decStr;
}

CString CMFCApplication1Dlg::HexToBinary(CString _number) {
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

CString CMFCApplication1Dlg::GetTCPFlagToBin(CString _Flag) {
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


CString CMFCApplication1Dlg::GetTCPFlagToLongStr(CString _Flag) {
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

void CMFCApplication1Dlg::SetDataToPacketData(CString FrameNumber, CString Time, CString Source, CString Destination, CString Protocol, CString Length, CString Info, CString Packet_Dump_Data) {
	HTREEITEM  PacketDataRoot1 = NULL;
	HTREEITEM  PacketDataRoot2 = NULL;
	HTREEITEM  PacketDataRoot3 = NULL;
	HTREEITEM  PacketDataRoot4 = NULL;
	HTREEITEM  PacketDataRoot5 = NULL;

	m_PacketDataTreeCtrl.DeleteAllItems();
	m_PacketDataTreeCtrl.Invalidate();

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

	CString Destination_addr = MakeIPAddressV6(Packet_Dump_Data.Mid(0, 2), Packet_Dump_Data.Mid(2, 2), Packet_Dump_Data.Mid(4, 2), Packet_Dump_Data.Mid(6, 2), Packet_Dump_Data.Mid(8, 2), Packet_Dump_Data.Mid(10, 2));
	CString Source_addr = MakeIPAddressV6(Packet_Dump_Data.Mid(12, 2), Packet_Dump_Data.Mid(14, 2), Packet_Dump_Data.Mid(16, 2), Packet_Dump_Data.Mid(18, 2), Packet_Dump_Data.Mid(20, 2), Packet_Dump_Data.Mid(22, 2));

	PacketDataLine2 = L"Ethernet ⅠⅠ, Src: " + Source_addr + L", Dst: " + Destination_addr;
	CString PakcetDataLine2by1 = L"Destination: " + Destination_addr;
	CString PakcetDataLine2by2 = L"Source: " + Source_addr;

	// IPv6 일때 작동하도록 수정
	CString Type = Packet_Dump_Data.Mid(24, 4);
	CString TypeName;
	CString Padding;
	if (Type == L"0800") {
		TypeName = L"IPv4";
		Padding = Packet_Dump_Data.Mid(108, 12);
	} else if (Type == L"0806") {
		TypeName = L"ARP";
		Padding = Packet_Dump_Data.Mid(84, 36);
	}
	CString PakcetDataLine2by3 = L"Type: " + TypeName + L" (0x" + Type + L")";


	CString PakcetDataLine2by4 = L"Padding: " + Padding;

	CString ipVersion = Packet_Dump_Data.Mid(28, 1);
	CString headerLength = Packet_Dump_Data.Mid(29, 1);

	CString totalLength = Calculate4HexNumber(Packet_Dump_Data.Mid(32, 1), Packet_Dump_Data.Mid(33, 1), Packet_Dump_Data.Mid(34, 1), Packet_Dump_Data.Mid(35, 1));
	CString identification = Calculate4HexNumber(Packet_Dump_Data.Mid(36, 1), Packet_Dump_Data.Mid(37, 1), Packet_Dump_Data.Mid(38, 1), Packet_Dump_Data.Mid(39, 1));

	CString timeToLive = Calculate2HexNumber(Packet_Dump_Data.Mid(44, 1), Packet_Dump_Data.Mid(45, 1));
	CString ptotocol = Calculate2HexNumber(Packet_Dump_Data.Mid(46, 1), Packet_Dump_Data.Mid(47, 1));

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

	CString Line4SourcePort = Calculate4HexNumber(Packet_Dump_Data.Mid(68, 1), Packet_Dump_Data.Mid(69, 1), Packet_Dump_Data.Mid(70, 1), Packet_Dump_Data.Mid(71, 1));
	CString Line4DestinationPort = Calculate4HexNumber(Packet_Dump_Data.Mid(72, 1), Packet_Dump_Data.Mid(73, 1), Packet_Dump_Data.Mid(74, 1), Packet_Dump_Data.Mid(75, 1));

	// Line 1
	PacketDataRoot1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine1);
	HTREEITEM PacketDataRoot1Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child1Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1by1, PacketDataRoot1Child1);
	HTREEITEM PacketDataRoot1Child1Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by1by2, PacketDataRoot1Child1);

	HTREEITEM PacketDataRoot1Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by2, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child3 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by3, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child4 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by4, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child5 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by5, PacketDataRoot1);
	HTREEITEM PacketDataRoot1Child6 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine1by6, PacketDataRoot1);

	// Line 2
	PacketDataRoot2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine2);
	HTREEITEM PacketDataRoot2Child1 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by1, PacketDataRoot2);
	HTREEITEM PacketDataRoot2Child2 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by2, PacketDataRoot2);
	HTREEITEM PacketDataRoot2Child3 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by3, PacketDataRoot2);
	if (Length == L"60") {
		HTREEITEM PacketDataRoot2Child4 = m_PacketDataTreeCtrl.InsertItem(PakcetDataLine2by4, PacketDataRoot2);
	}
	// Line 3
	PacketDataRoot3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3);
	HTREEITEM PacketDataRoot3Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by1, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by2, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by3, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by4, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by5, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by6, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by7, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by8, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by9, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by10, PacketDataRoot3);
	HTREEITEM PacketDataRoot3Child11 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine3by11, PacketDataRoot3);

	if (Protocol == L"TCP") {
		PacketDataLine4 = L"Transmission Control Protocol, Src Port: " + Line4SourcePort + L", Dst Port: " + Line4DestinationPort;
		CString PacketDataLine4by1 = L"Source Port: " + Line4SourcePort;
		CString PacketDataLine4by2 = L"Destination Port: " + Line4DestinationPort;
		CString PacketDataLine4by3 = L"Sequence number: " + Packet_Dump_Data.Mid(76, 8);
		CString PacketDataLine4by4 = L"Acknowledge number: " + Packet_Dump_Data.Mid(84, 8);
		CString PacketDataLine4by5 = HexToBinary(HexToDec(Packet_Dump_Data.Mid(92, 1))) + L" . . . . = Header Length: "
			+ CString(std::to_string(_ttoi(Packet_Dump_Data.Mid(92, 1)) * 4).c_str()) + " bytes ("
			+ CString(std::to_string(_ttoi(Packet_Dump_Data.Mid(92, 1))).c_str()) + ")";

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
		CString PacketDataLine4by6by11 = L"[TCP Flags: " + TCPFlagLongStr + "]";

		PacketDataLine4by6by1 = Reserved + L".  . . . .  . . . . = Reserved: " + GetFlagSetNotSet(Reserved);		// Reserved
		PacketDataLine4by6by2 = L". . ." + Nonce + L"  . . . .  . . . . = Nonce: " + GetFlagSetNotSet(Nonce);		// Nonce
		PacketDataLine4by6by3 = L". . . .  " + CongestionWindowReduced + L". . .  . . . . = CongestionWindowReduced (CWR) : " + GetFlagSetNotSet(CongestionWindowReduced);		// CongestionWindowReduced
		PacketDataLine4by6by4 = L". . . .  . " + ECN_Echo + L". .  . . . . = ECN-Echo : " + GetFlagSetNotSet(ECN_Echo);		// ECN_Echo
		PacketDataLine4by6by5 = L". . . .  . . " + Urgent + L".  . . . . = Urgent : " + GetFlagSetNotSet(Urgent);		// Urgent
		PacketDataLine4by6by6 = L". . . .  . . ." + Acknowledgment + L"  . . . . = Acknowledgment : " + GetFlagSetNotSet(Acknowledgment);		// Acknowledgment
		PacketDataLine4by6by7 = L". . . .  . . . .  " + Push + L". . . = Push : " + GetFlagSetNotSet(Push);		// Push
		PacketDataLine4by6by8 = L". . . .  . . . .  . " + Reset + L". . = Reset : " + GetFlagSetNotSet(Reset);		// Reset
		PacketDataLine4by6by9 = L". . . .  . . . .  . . " + Syn + L". = Syn : " + GetFlagSetNotSet(Syn);		// Syn
		PacketDataLine4by6by10 = L". . . .  . . . .  . . ." + Fin + L" = Fin : " + GetFlagSetNotSet(Fin);		// Fin

		CString windowSize = Calculate4HexNumber(Packet_Dump_Data.Mid(96, 1), Packet_Dump_Data.Mid(97, 1), Packet_Dump_Data.Mid(98, 1), Packet_Dump_Data.Mid(99, 1));
		CString urgentPointer = Calculate4HexNumber(Packet_Dump_Data.Mid(104, 1), Packet_Dump_Data.Mid(105, 1), Packet_Dump_Data.Mid(106, 1), Packet_Dump_Data.Mid(107, 1));

		CString PacketDataLine4by7 = L"Window size value: " + windowSize;
		CString PacketDataLine4by8 = L"[Calculated window size: " + windowSize + L"]";
		CString PacketDataLine4by9 = L"Checksum: 0x" + Packet_Dump_Data.Mid(100, 4);
		CString PacketDataLine4by10 = L"Urgent pointer: " + urgentPointer;

		// Line 4
		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by1, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by2, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by3, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by4, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by5, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by6, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by7, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by8, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by9, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by10, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child6Child11 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6by11, PacketDataRoot4Child6);
		HTREEITEM PacketDataRoot4Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by9, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child10 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by10, PacketDataRoot4);
	} else if (Protocol == L"UDP") {
		PacketDataLine4 = L"User Datagram protocol, Src Port: " + Line4SourcePort + L", Dst Port: " + Line4DestinationPort;

		CString Length = Calculate4HexNumber(Packet_Dump_Data.Mid(76, 1), Packet_Dump_Data.Mid(77, 1), Packet_Dump_Data.Mid(78, 1), Packet_Dump_Data.Mid(79, 1));

		CString PacketDataLine4by1 = L"Source Port: " + Line4SourcePort;
		CString PacketDataLine4by2 = L"Destination Port: " + Line4DestinationPort;
		CString PacketDataLine4by3 = L"Length: " + Length;
		CString PacketDataLine4by4 = L"Checksum: 0x" + Packet_Dump_Data.Mid(80, 4);

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM  PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM  PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);

		CString UDPData = Packet_Dump_Data.Mid(84, _ttoi(Length));
		CString UDPDataLength = CString(std::to_string(UDPData.GetLength()).c_str());

		CString PacketDataLine5 = L"Data (" + UDPDataLength + " bytes )";
		CString PacketDataLine5by1 = L"Data: " + UDPData.Mid(0, 40).MakeUpper() + L"...";
		CString PacketDataLine5by2 = L"[Length: " + UDPDataLength + L"]";

		PacketDataRoot5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine5);
		HTREEITEM PacketDataRoot5Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine5by1, PacketDataRoot5);
		HTREEITEM PacketDataRoot5Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine5by2, PacketDataRoot5);

	} else if (Protocol == L"ARP") {
		PacketDataLine4 = L"Address Resolution Protocol";

		CString HardwareTypeNumber = Calculate4HexNumber(Packet_Dump_Data.Mid(28, 1), Packet_Dump_Data.Mid(29, 1), Packet_Dump_Data.Mid(30, 1), Packet_Dump_Data.Mid(31, 1));
		CString HardwareTypeStr = ArpHardwareType(HardwareTypeNumber);
		CString ProtocolType = Packet_Dump_Data.Mid(32, 4);
		CString HardwareSize = Calculate2HexNumber(Packet_Dump_Data.Mid(36, 1), Packet_Dump_Data.Mid(37, 1));
		CString ProtocolSize = Calculate2HexNumber(Packet_Dump_Data.Mid(38, 1), Packet_Dump_Data.Mid(39, 1));
		CString OpCodeNumber = Calculate4HexNumber(Packet_Dump_Data.Mid(40, 1), Packet_Dump_Data.Mid(41, 1), Packet_Dump_Data.Mid(42, 1), Packet_Dump_Data.Mid(43, 1));
		CString OpCodeStr = ArpOpcde(OpCodeNumber);
		CString SenderMacAddr = MakeIPAddressV6(Packet_Dump_Data.Mid(44, 2), Packet_Dump_Data.Mid(46, 2), Packet_Dump_Data.Mid(48, 2), Packet_Dump_Data.Mid(50, 2), Packet_Dump_Data.Mid(52, 2), Packet_Dump_Data.Mid(54, 2));
		CString SenderIpAddr = Source;
		CString TargetMacAddr = MakeIPAddressV6(Packet_Dump_Data.Mid(64, 2), Packet_Dump_Data.Mid(66, 2), Packet_Dump_Data.Mid(68, 2), Packet_Dump_Data.Mid(70, 2), Packet_Dump_Data.Mid(72, 2), Packet_Dump_Data.Mid(74, 2));;
		CString TargetIpAddr = Destination;

		CString PacketDataLine4by1 = L"Hardware type: " + HardwareTypeStr + L" (" + HardwareTypeNumber + L")";
		CString PacketDataLine4by2 = L"Protocol type: IPv4 (0x" + ProtocolType + L")";
		CString PacketDataLine4by3 = L"Hardware size: " + HardwareSize;
		CString PacketDataLine4by4 = L"Protocol size: " + ProtocolSize;
		CString PacketDataLine4by5 = L"Opcode: " + OpCodeStr + L" (" + OpCodeNumber + L")";
		CString PacketDataLine4by6 = L"Sender MAC address: " + SenderMacAddr;
		CString PacketDataLine4by7 = L"Sender IP address: " + SenderIpAddr;
		CString PacketDataLine4by8 = L"Target MAC address: " + TargetMacAddr;
		CString PacketDataLine4by9 = L"Target IP address: " + TargetIpAddr;

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child9 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by9, PacketDataRoot4);

	} else if (Protocol == L"ICMP") {
		PacketDataLine4 = L"Ineternet Control Message Protocol";

		CString ICMPType = Calculate2HexNumber(Packet_Dump_Data.Mid(68, 1), Packet_Dump_Data.Mid(69, 1));
		CString ICMPCode = Calculate2HexNumber(Packet_Dump_Data.Mid(70, 1), Packet_Dump_Data.Mid(71, 1));
		CString ICMPChecksum = Packet_Dump_Data.Mid(72, 4);

		CString ICMPIdentifierBEDec = Calculate4HexNumber(Packet_Dump_Data.Mid(76, 1), Packet_Dump_Data.Mid(77, 1), Packet_Dump_Data.Mid(78, 1), Packet_Dump_Data.Mid(79, 1));
		CString ICMPIdentifierBEHex = Packet_Dump_Data.Mid(76, 4);

		CString ICMPIdentifierLEDec = Calculate4HexNumber(Packet_Dump_Data.Mid(78, 1), Packet_Dump_Data.Mid(79, 1), Packet_Dump_Data.Mid(76, 1), Packet_Dump_Data.Mid(77, 1));
		CString ICMPIdentifierLEHex = Packet_Dump_Data.Mid(78, 2) + Packet_Dump_Data.Mid(76, 2);

		CString ICMPSquenceNumberBEDec = Calculate4HexNumber(Packet_Dump_Data.Mid(80, 1), Packet_Dump_Data.Mid(81, 1), Packet_Dump_Data.Mid(82, 1), Packet_Dump_Data.Mid(83, 1));
		CString ICMPSquenceNumberBEHex = Packet_Dump_Data.Mid(80, 4);

		CString ICMPSquenceNumberLEDec = Calculate4HexNumber(Packet_Dump_Data.Mid(82, 1), Packet_Dump_Data.Mid(83, 1), Packet_Dump_Data.Mid(80, 1), Packet_Dump_Data.Mid(81, 1));
		CString ICMPSquenceNumberLEHex = Packet_Dump_Data.Mid(82, 2) + Packet_Dump_Data.Mid(80, 2);
		CString ICMPData = Packet_Dump_Data.Mid(84, _ttoi(Length));
		CString ICMPDataLength = CString(std::to_string(ICMPData.GetLength()).c_str());

		CString PacketDataLine4by1 = L"Type: " + ICMPType;
		CString PacketDataLine4by2 = L"Code: " + ICMPCode;
		CString PacketDataLine4by3 = L"Checksum: " + ICMPChecksum;
		CString PacketDataLine4by4 = L"Identifier (BE): " + ICMPIdentifierBEDec + L" (0x" + ICMPIdentifierBEHex + L")";
		CString PacketDataLine4by5 = L"Identifier (LE): " + ICMPIdentifierLEDec + L" (0x" + ICMPIdentifierLEHex + L")";
		CString PacketDataLine4by6 = L"Sequence number (BE): " + ICMPSquenceNumberBEDec + L" (0x" + ICMPSquenceNumberBEHex + L")";
		CString PacketDataLine4by7 = L"Sequence number (LE): " + ICMPSquenceNumberLEDec + L" (0x" + ICMPSquenceNumberLEHex + L")";
		CString PacketDataLine4by8 = L"Data (" + ICMPDataLength + " bytes )";
		CString PacketDataLine4by8by1 = L"Data :" + ICMPData;

		PacketDataRoot4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4);
		HTREEITEM PacketDataRoot4Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by1, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child2 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by2, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child3 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by3, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child4 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by4, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child5 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by5, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child6 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by6, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child7 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by7, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child8 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8, PacketDataRoot4);
		HTREEITEM PacketDataRoot4Child8Child1 = m_PacketDataTreeCtrl.InsertItem(PacketDataLine4by8by1, PacketDataRoot4Child8);
	}

	m_PacketDataTreeCtrl.Expand(PacketDataRoot1, TVE_EXPAND);
	m_PacketDataTreeCtrl.Expand(PacketDataRoot2, TVE_EXPAND);
	m_PacketDataTreeCtrl.Expand(PacketDataRoot3, TVE_EXPAND);
	m_PacketDataTreeCtrl.Expand(PacketDataRoot4, TVE_EXPAND);
	m_PacketDataTreeCtrl.Expand(PacketDataRoot5, TVE_EXPAND);

	m_PacketDataTreeCtrl.Invalidate();
	m_PacketDataTreeCtrl.UpdateWindow();
}


void CMFCApplication1Dlg::SetDataToHDXEditor(CString Packet_dump_data) {
	if (Packet_dump_data != L"") {
		for (int i = 0; i < Packet_dump_data.GetLength() + 1; i += 32) {
			int column_count = m_PacketDumpListCtrl.GetItemCount();
			CString column_count_str;
			column_count_str.Format(_T("%d"), column_count + 1);

			std::stringstream stream;
			stream << std::setw(6) << std::setfill('0') << std::hex << (i / 2);

			std::string seq_number_str = stream.str();
			LPCSTR lpcstrSeqNum = (LPCSTR)seq_number_str.c_str();
			USES_CONVERSION;
			CString CstrSeqNum = A2CT(lpcstrSeqNum);
			CstrSeqNum.MakeUpper();
			m_PacketDumpListCtrl.InsertItem(column_count, CstrSeqNum);

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

			m_PacketDumpListCtrl.SetItem(column_count, 1, LVIF_TEXT, hex1, NULL, NULL, NULL, NULL);
			m_PacketDumpListCtrl.SetItem(column_count, 2, LVIF_TEXT, hex2, NULL, NULL, NULL, NULL);

			CString convAscii;
			CString PacketAscii1;
			CString PacketAscii2;

			for (int i = 0; i < AsciiAllHex.GetLength(); i += 2) {
				PacketAscii1 = HexToDec(AsciiAllHex.Mid(i, 1));
				PacketAscii2 = HexToDec(AsciiAllHex.Mid(i + 1, 1));

				int ten = _ttoi(PacketAscii1) * 16;
				int one = _ttoi(PacketAscii2);

				int sum = ten + one;
				ten = 0;
				one = 0;

				if (sum < 32 || sum>128) {
					sum = 46;
				}

				char ascii[4];
				ascii[0] = (char)sum;
				if (sum == 46) {
					sprintf(ascii, "%2c", ascii[0]);
				} else {
					sprintf(ascii, "%c", ascii[0]);
				}
				convAscii += ascii;
			}

			m_PacketDumpListCtrl.SetItem(column_count, 3, LVIF_TEXT, convAscii, NULL, NULL, NULL, NULL);
		}
	}
}

CString CMFCApplication1Dlg::GetFlagSetNotSet(CString _Flag) {
	int Length = _Flag.GetLength();

	if (Length == 3) {
		return (_Flag.Compare(L"000") == 0) ? L"Not set" : L"Set";
	}
	if (Length == 1) {
		return (_Flag.Compare(L"0") == 0) ? L"Not set" : L"Set";
	}
	return L"";
}

CString CMFCApplication1Dlg::Calculate4HexNumber(CString num1, CString num2, CString num3, CString num4) {
	return CString(std::to_string((
		_ttoi(HexToDec(num1)) * 16 * 16 * 16 +
		_ttoi(HexToDec(num2)) * 16 * 16 +
		_ttoi(HexToDec(num3)) * 16 +
		_ttoi(HexToDec(num4)) * 1
		)).c_str());
}

CString CMFCApplication1Dlg::Calculate2HexNumber(CString num1, CString num2) {
	return CString(std::to_string((
		_ttoi(HexToDec(num1)) * 16 +
		_ttoi(HexToDec(num2)) * 1
		)).c_str());
}

CString CMFCApplication1Dlg::MakeIPAddressV6(CString Aclass, CString Bclass, CString Cclass, CString Dclass, CString Eclass, CString Fclass) {
	return Aclass + L":" + Bclass + L":" + Cclass + L":" + Dclass + L":" + Eclass + L":" + Fclass;
}

void CMFCApplication1Dlg::OnBnClickedFilterApplyButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (_access(file_name_write, 0)!=0) {
		MessageBox(_T("캡쳐된 패킷이 없습니다."), _T("오류"), MB_ICONWARNING);
		return;
	}

	UpdateData(TRUE);
	GetDlgItemText(IDC_EDIT1, Filter);

	// 필터가 빈칸이 아닐때만 작업진행
	if (true) {
		IsFilterApply = TRUE;

		if (m_FileReadThread == NULL) {
			//ClearPacketCnt();
			m_PacketCapturedListCtrl.DeleteAllItems();
			m_PacketDataTreeCtrl.DeleteAllItems();
			m_PacketDumpListCtrl.DeleteAllItems();

			m_FileReadThread = AfxBeginThread(FileReadThreadFunction, this);
			m_FileReadThreadWorkType = RUNNING;
		} else {
			DWORD dwResult;

			m_FileReadThread->SuspendThread();
			m_FileReadThreadWorkType = STOP;
			::GetExitCodeThread(m_FileReadThread->m_hThread, &dwResult);
			delete m_FileReadThread;
			m_FileReadThread = NULL;

			//ClearPacketCnt();
			m_PacketCapturedListCtrl.DeleteAllItems();
			m_PacketDataTreeCtrl.DeleteAllItems();
			m_PacketDumpListCtrl.DeleteAllItems();

			if (m_FileReadThread == NULL) {
				m_FileReadThread = AfxBeginThread(FileReadThreadFunction, this);
				m_FileReadThreadWorkType = RUNNING;
			}
		}
	}

	RemoveMouseMessage();
}

CString CMFCApplication1Dlg::ArpOpcde(CString OpcodeNumber) {
	CString OpcodeStr = L"";
	if (OpcodeNumber.Compare(L"1") == 0) {
		OpcodeStr = "Request";
	} else if (OpcodeNumber.Compare(L"2") == 0) {
		OpcodeStr = "Reply";
	}
	return OpcodeStr;
}

CString CMFCApplication1Dlg::ArpHardwareType(CString HardwareTypeNumber) {
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

// 필터 적용시에 패킷 정보를 파일에서 읽어들이는 쓰레드 함수
UINT CMFCApplication1Dlg::FileReadThreadFunction(LPVOID _mothod) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;
	long long start_pos = 0;

	CString NO, TIME, SIP, DIP, PROTO, LENGTH, INFO, DUMP;
	std::ifstream is;
	int i = 0;

	int prev_column_index = 0;

	while (1) {
		is.open(pDlg->file_name_write);
		is.seekg(0, is.end);
		long long end_pos = is.tellg();

		is.seekg(start_pos, is.beg);

		std::string str;
		int column_cnt = 0;

		if (start_pos < end_pos) {
			for (i = start_pos; i < end_pos; ) {
				std::getline(is, str);

				i++;
				if (column_cnt == 0) {
					NO = (CString)str.c_str();
				} else if (column_cnt == 1) {
					TIME = (CString)str.c_str();
				} else if (column_cnt == 2) {
					SIP = (CString)str.c_str();
				} else if (column_cnt == 3) {
					DIP = (CString)str.c_str();
				} else if (column_cnt == 4) {
					PROTO = (CString)str.c_str();
				} else if (column_cnt == 5) {
					LENGTH = (CString)str.c_str();
				} else if (column_cnt == 6) {
					INFO = (CString)str.c_str();
				} else if (column_cnt > 6) {
					if (str != "END") {
						DUMP += (CString)str.c_str();
					}
				}

				if (str == "END") {
					PROTO.Replace(L" ", L"");
					DUMP.Replace(L" ", L"");
					DUMP.Replace(L"\n", L"");

					std::vector<CString> prop_vec;
					std::vector<CString>::iterator prop_iter;
					prop_vec.push_back(TIME);
					prop_vec.push_back(SIP);
					prop_vec.push_back(DIP);
					prop_vec.push_back(PROTO);
					prop_vec.push_back(LENGTH);
					prop_vec.push_back(NO);
					prop_vec.push_back(DUMP);

					int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

					CString column_count_str;
					column_count_str.Format(_T("%d"), column_count + 1);

					if (!(PROTO != L"TCP" && PROTO != L"UDP" && PROTO != L"ARP" && PROTO != L"ICMP")) {
						if (prev_column_index < _ttoi(NO)) {
							prev_column_index = _ttoi(NO);
							// 필터 적용
							if (pDlg->CheckFilter(pDlg->Filter, prop_vec)) {
								if (column_count == 0) {
									column_count_str.Format(_T("%d"), column_count + 1);
									pDlg->SetDataToPacketData(column_count_str, TIME, SIP, DIP, PROTO, LENGTH, NULL, DUMP);
									pDlg->SetDataToHDXEditor(DUMP);
								}

								pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);
								for (int j = 1; j < 8; j++) {
									pDlg->m_PacketCapturedListCtrl.SetItem(column_count, j, LVIF_TEXT, prop_vec[j - 1], NULL, NULL, NULL, NULL);
								}
								int nCount = pDlg->m_PacketCapturedListCtrl.GetItemCount();
								pDlg->m_PacketCapturedListCtrl.EnsureVisible(nCount - 1, FALSE);
							}
						}
					}

					for (prop_iter = prop_vec.begin(); prop_iter != prop_vec.end(); prop_iter++) {
						(*prop_iter) = L"";
					}
					DUMP = L"";

					column_cnt = 0;
				} else {
					column_cnt++;
				}
			}
		}
		is.close();
		start_pos = i;
	}
	return 0;
}

void CMFCApplication1Dlg::OpenPacketDataFile() {
	// TODO: 여기에 명령 처리기 코드를 추가합니다.
	TCHAR szFilter[] = _T("All Files(*.*)|*.*||");
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, szFilter);
	dlg.DoModal();

	CString strPathName = dlg.GetPathName();
	this->file_name_read = strPathName;

	m_PacketCapturedListCtrl.DeleteAllItems();
	m_PacketDataTreeCtrl.DeleteAllItems();
	m_PacketDumpListCtrl.DeleteAllItems();

	if (strPathName.GetLength() > 50) {
		strPathName = strPathName.Right(strPathName.GetLength() - strPathName.ReverseFind('\\') - 1);
	}
	SetDlgItemText(IDC_STATIC_NET, L"Selected: " + strPathName);

	CheckDlgButton(IDC_CHECK2, TRUE);

	if (m_FileOpenThread == NULL) {
		m_FileOpenThread = AfxBeginThread(FileOpenThreadFunction, this);
		m_FileOpenThreadWorkType = RUNNING;
	}
}

void CMFCApplication1Dlg::FileSave() {
	// TODO: 여기에 명령 처리기 코드를 추가합니다.
	if (MessageBox(_T("파일을 저장 하시겠습니까?"), _T("파일 저장"), MB_YESNO | MB_ICONQUESTION) == IDYES) {
		is_file_save = TRUE;
	} else {
		is_file_save = FALSE;
	}
}

// 파일을 열었을 경우에 사용하는 쓰레드 함수
UINT CMFCApplication1Dlg::FileOpenThreadFunction(LPVOID _mothod) {
	CMFCApplication1Dlg* pDlg = (CMFCApplication1Dlg*)AfxGetApp()->m_pMainWnd;

	pDlg->ClearPacketCnt();

	CString NO, TIME, SIP, DIP, PROTO, LENGTH, INFO, DUMP;
	char file_name[100];
	char cstr[10];
	CT2CA pszConvertedAnsiString(pDlg->file_name_read);
	std::string file_name_str(pszConvertedAnsiString);
	strcpy(file_name, file_name_str.c_str());
	std::string str = "FILEOPEN?";

	std::ifstream is(file_name, std::ios::out);

	int cnt = 0;
	int i = 0;
	if (is) {
		int column_cnt = 0;
		while (!str.empty()) {
			std::getline(is, str);

			if (column_cnt == 0) {
				NO = (CString)str.c_str();
			} else if (column_cnt == 1) {
				TIME = (CString)str.c_str();
			} else if (column_cnt == 2) {
				SIP = (CString)str.c_str();
			} else if (column_cnt == 3) {
				DIP = (CString)str.c_str();
			} else if (column_cnt == 4) {
				PROTO = (CString)str.c_str();
			} else if (column_cnt == 5) {
				LENGTH = (CString)str.c_str();
			} else if (column_cnt == 6) {
				INFO = (CString)str.c_str();
			} else if (column_cnt > 6) {
				if (str != "END") {
					DUMP += (CString)str.c_str();
				}
			}

			if (str == "END") {
				PROTO.Replace(L" ", L"");
				DUMP.Replace(L" ", L"");
				DUMP.Replace(L"\n", L"");

				std::vector<CString> prop_vec;
				std::vector<CString>::iterator prop_iter;
				prop_vec.push_back(TIME);
				prop_vec.push_back(SIP);
				prop_vec.push_back(DIP);
				prop_vec.push_back(PROTO);
				prop_vec.push_back(LENGTH);
				prop_vec.push_back(NO);
				prop_vec.push_back(DUMP);


				int column_count = pDlg->m_PacketCapturedListCtrl.GetItemCount();

				for (prop_iter = prop_vec.begin(); prop_iter != prop_vec.end(); prop_iter++) {
					if ((*prop_iter).IsEmpty() || (PROTO != L"TCP" && PROTO != L"UDP" && PROTO != L"ARP" && PROTO != L"ICMP")) {
						return 0;
					}
				}

				CString column_count_str;
				column_count_str.Format(_T("%d"), column_count + 1);
				pDlg->m_PacketCapturedListCtrl.InsertItem(column_count, column_count_str);

				/* 첫 패킷이면 데이터 세팅*/
				if (column_count == 0) {
					column_count_str.Format(_T("%d"), column_count + 1);
					pDlg->SetDataToPacketData(column_count_str, TIME, SIP, DIP, PROTO, LENGTH, NULL, DUMP);
					pDlg->SetDataToHDXEditor(DUMP);
				}

				for (int i = 1; i < 8; i++) {
					pDlg->m_PacketCapturedListCtrl.SetItem(column_count, i, LVIF_TEXT, prop_vec[i - 1], NULL, NULL, NULL, NULL);
				}

				int nCount = pDlg->m_PacketCapturedListCtrl.GetItemCount();
				pDlg->m_PacketCapturedListCtrl.EnsureVisible(nCount - 1, FALSE);

				PROTO == L"TCP" ? pDlg->tcp_pkt_cnt++ : pDlg->tcp_pkt_cnt;
				PROTO == L"UDP" ? pDlg->udp_pkt_cnt++ : pDlg->udp_pkt_cnt;
				PROTO == L"ICMP" ? pDlg->icmp_pkt_cnt++ : pDlg->icmp_pkt_cnt;
				PROTO == L"ARP" ? pDlg->arp_pkt_cnt++ : pDlg->arp_pkt_cnt;

				pDlg->packet_cnt++;
				pDlg->ChangeStaticText(pDlg->packet_cnt, pDlg->tcp_pkt_cnt, pDlg->udp_pkt_cnt, pDlg->arp_pkt_cnt, pDlg->icmp_pkt_cnt);

				for (prop_iter = prop_vec.begin(); prop_iter != prop_vec.end(); prop_iter++) {
					(*prop_iter).Empty();
				}

				column_cnt = 0;
			} else {
				column_cnt++;
			}
		}
		is.close();
	}

	pDlg->CheckDlgButton(IDC_CHECK2, TRUE);
	pDlg->m_FileOpenThreadWorkType = STOP;
	pDlg->m_FileOpenThread = NULL;

	return 0;
}

void CMFCApplication1Dlg::OnClose() {
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	if (MessageBox(_T("프로그램을 종료 하시겠습니까?"), _T("프로그램 종료"), MB_YESNO | MB_ICONQUESTION) == IDYES) {
		DWORD dwResult;

		CWinThread* ThreadArray[3] = { m_PacketCaptrueThread, m_FileReadThread, m_FileOpenThread };
		ThreadWorking ThreadStatus[3] = { m_PacketCaptureThreadWorkType,m_FileReadThreadWorkType,m_FileOpenThreadWorkType };

		for (int i = 0; i < 3; i++) {
			if (*(ThreadArray[i]) != NULL) {
				ThreadArray[i]->SuspendThread();
				ThreadStatus[i] = STOP;
				::GetExitCodeThread(ThreadArray[i]->m_hThread, &dwResult);
				delete ThreadArray[i];
				ThreadArray[i] = NULL;
			}
		}

		if (!is_file_save) {
			std::remove(file_name_write);
		}

		CDialogEx::OnClose();
	} else {
		// 프로그램을 종료 하지 않음
	}
}



// 필터 체크하는 함수
BOOL CMFCApplication1Dlg::CheckFilter(CString Filter, std::vector<CString> vec) {
	// Filter는 입력된 필터 값
	// vec은 캡쳐된 패킷의 정보
	BOOL result = FALSE;

	if (Filter == L"" || Filter == DefaultFilterValue) {
		result = TRUE;
		return result;
	}

	CString PROTOCOL = vec[3];
	PROTOCOL.Replace(L" ", L"");

	Filter = Filter.MakeUpper();
	Filter = Filter.TrimLeft();
	Filter = Filter.TrimRight();

	int FilterLength = Filter.GetLength();

	if (FilterLength == 3 || FilterLength == 4) {
		if (Filter == PROTOCOL) {
			result = TRUE;	
		} else {
			result = FALSE;
		}

		return result;
	}

	const char* filter_file = "filter.dat";

	CString read_line;
	std::string in_line;
	std::ifstream in(filter_file);
	if (!in.is_open()) {
		return FALSE;
	}
	while (getline(in, in_line)) {
		read_line = (CString)in_line.c_str();
		read_line = read_line.TrimLeft();
		read_line = read_line.TrimRight();
		if (read_line.Compare(Filter) == 0) {
			break;
		}
	}
	in.close();

	CString SplitOPor = L"OR";
	CString SplitOPand = L"AND";
	int op_cnt = GetCountStr(Filter, SplitOPor);

	std::vector<int> index_vec;

	index_vec = GetCountStrIdx(Filter, SplitOPor);

	std::vector<CString> split_vec;
	split_vec = SplitStr(Filter, SplitOPor);

	std::vector<CString>::iterator split_iter;

	for(split_iter = split_vec.begin(); split_iter != split_vec.end(); split_iter++) {
		if (*split_iter == PROTOCOL) {
			result = TRUE;
			break;
		}
	}

	/*
	최소   
	port == 1    -   9
	port == 65536    -  13
	port ==  1 or ip == 0.0.0.0   - 26
	port == 65536 and ip == 123.123.123.123  - 39


	ip == 0.0.0.0    - 13
	ip == 123.123.123.123  - 21
	ip == 0.0.0.0 or port == 1   - 26
	ip == 123.123.123.123 and port == 65536  - 39
	*/

	CString SplitIP = Filter.Mid(0, 6);
	CString SplitPort = Filter.Mid(0, 8);
	if (SplitIP == L"IP == ") {
		if (Filter.GetLength() >= 13 && Filter.GetLength()<=21) {
			SplitIP = Filter.Mid(6, Filter.GetLength()-6);
		} else if (Filter.GetLength() > 21 && Filter.GetLength() <= 39) {
		}



	} else if (SplitPort == L"PORT == ") {

	}

	


	return result;
}



int GetCountStr(CString target_str, CString target_find_str) {
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

std::vector<int> GetCountStrIdx(CString target_str, CString target_find_str) {
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


std::vector<CString> SplitStr(CString target_str, CString target_find_str) {
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

BOOL CMFCApplication1Dlg::RemoveMouseMessage(void) {
	MSG msg;
	while (PeekMessage(&msg, NULL, WM_LBUTTONDOWN, WM_MBUTTONDBLCLK, PM_REMOVE));
	return TRUE;
}