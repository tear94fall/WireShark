// NetworkInterfaceDlg.cpp: 구현 파일
//

#include "pch.h"
#include "MFCApplication1.h"
#include "NetworkInterfaceDlg.h"
#include "afxdialogex.h"

// NetworkInterfaceDlg 대화 상자

IMPLEMENT_DYNAMIC(NetworkInterfaceDlg, CDialogEx)

NetworkInterfaceDlg::NetworkInterfaceDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent) {
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

NetworkInterfaceDlg::~NetworkInterfaceDlg() {
}

void NetworkInterfaceDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, NetWorkListCtrl);
}


BEGIN_MESSAGE_MAP(NetworkInterfaceDlg, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &NetworkInterfaceDlg::OnBnClickedQuitButton)
	ON_BN_CLICKED(IDOK, &NetworkInterfaceDlg::OnBnClickedSelectInterfaceButton)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, &NetworkInterfaceDlg::OnNMClickList1)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &NetworkInterfaceDlg::OnHdnItemclickList1)
END_MESSAGE_MAP()


BOOL NetworkInterfaceDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, FALSE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	SetWindowText(_T("Wire Dolphin"));

	CRect rectangle;
	LV_COLUMN add_column;
	add_column.mask = LVCF_TEXT | LVCF_WIDTH;

	NetWorkListCtrl.GetWindowRect(&rectangle);
	NetWorkListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	const int column_property_count = 3;
	wchar_t* column_property_name[column_property_count] = { L"No", L"Network Interface", L"Network Name" };
	double column_porperty_width[column_property_count] = { 0.1,0.89,0 };

	for (int i = 0; i < column_property_count; i++) {
		add_column.pszText = column_property_name[i];
		add_column.cx = rectangle.Width() * column_porperty_width[i];
		NetWorkListCtrl.InsertColumn(i, &add_column);
	}

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		AfxMessageBox(CString(errbuf));
		return FALSE;
	}

	for (d = alldevs; d; d = d->next) {
		column_count = NetWorkListCtrl.GetItemCount();

		CString column_count_str;
		column_count_str.Format(_T("%d"), column_count + 1);
		NetWorkListCtrl.InsertItem(column_count, column_count_str);

		InterfaceDescription = ((LPSTR)d->description);
		InterfaceName = ((LPSTR)d->name);

		NetWorkListCtrl.SetItem(column_count, 1, LVIF_TEXT, InterfaceDescription, NULL, NULL, NULL, NULL);
		NetWorkListCtrl.SetItem(column_count, 2, LVIF_TEXT, InterfaceName, NULL, NULL, NULL, NULL);
	}

	if (column_count == 0) {
		MessageBox(_T("연결된 네트워크 인터페이스가 없습니다."), _T("오류"), MB_ICONASTERISK);
		m_nSelectedIndex = -1;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 예외: OCX 속성 페이지는 FALSE를 반환해야 합니다.
}

// NetworkInterfaceDlg 메시지 처리기


void NetworkInterfaceDlg::OnBnClickedQuitButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	this->CancelButtonClicked = true;


	CDialogEx::OnCancel();
}


bool NetworkInterfaceDlg::CancelButtonClickedFunction(void) {
	return CancelButtonClicked;
}


void NetworkInterfaceDlg::OnBnClickedSelectInterfaceButton() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	 //value

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 1);
	InterfaceDescription = m_strSelectedValue;

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 2);
	InterfaceName = m_strSelectedValue;

	if (m_nSelectedIndex == -1) {
		MessageBox(_T("Nothing Selected."), _T("Error"), MB_ICONWARNING);
		SetDlgItemText(IDC_STATIC, L"Select Interface");
	} else {
		CDialogEx::OnOK();
	}
}


void NetworkInterfaceDlg::OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	m_nSelectedIndex = pNMListView->iItem;

	if (m_nSelectedIndex != -1) {
		CString m_nSelectedValue;
		m_nSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 1);
		m_nSelectedValue = (CString)(std::to_string(m_nSelectedIndex + 1).c_str()) + L"." + m_nSelectedValue;
		if (m_nSelectedValue.GetLength() > 25) {
			m_nSelectedValue = m_nSelectedValue.Mid(0, 25) + L"...";
		}
		SetDlgItemText(IDC_STATIC, m_nSelectedValue + L" is Selected");
	} else {
		SetDlgItemText(IDC_STATIC, L"Selected nothing");
	}
	*pResult = 0;
}


void NetworkInterfaceDlg::OnHdnItemclickList1(NMHDR* pNMHDR, LRESULT* pResult) {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	LPNMHEADER pNMLV = reinterpret_cast<LPNMHEADER>(pNMHDR);

	// 선택된 헤더 숫자로 정렬해야되는 값은 0번 (No)와 5번 (Length)이다.

	for (int i = 0; i < (NetWorkListCtrl.GetItemCount()); i++) {
		NetWorkListCtrl.SetItemData(i, i);
	}
	*pResult = 0;
}

BOOL NetworkInterfaceDlg::PreTranslateMessage(MSG* pMsg) {
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.

	if (pMsg->message == WM_KEYDOWN) {
		if (pMsg->wParam == VK_ESCAPE)
			return TRUE;
		else if (pMsg->wParam == VK_RETURN)
			return TRUE;
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}