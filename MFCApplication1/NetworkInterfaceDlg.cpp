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
	ON_BN_CLICKED(IDCANCEL, &NetworkInterfaceDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDOK, &NetworkInterfaceDlg::OnBnClickedOk)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, &NetworkInterfaceDlg::OnNMClickList1)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &NetworkInterfaceDlg::OnHdnItemclickList1)
END_MESSAGE_MAP()


BOOL NetworkInterfaceDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, FALSE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	SetWindowText(_T("Wire Dolphin"));

	CRect rt;
	NetWorkListCtrl.GetWindowRect(&rt);
	NetWorkListCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	LV_COLUMN add_column;
	// 컬럼 속성을 지정한다. 텍스트 형식을 사용하고 폭을 명시하겠다고 설정한다.

	add_column.mask = LVCF_TEXT | LVCF_WIDTH;
	add_column.pszText = L"No";
	add_column.cx = rt.Width() * 0.1;
	NetWorkListCtrl.InsertColumn(0, &add_column);

	// Description
	add_column.pszText = L"Network Interface";
	add_column.cx = rt.Width() * 0.89;
	NetWorkListCtrl.InsertColumn(1, &add_column);

	// name
	add_column.pszText = L"Network Interface";
	add_column.cx = rt.Width() * 0;
	NetWorkListCtrl.InsertColumn(2, &add_column);

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
		// netInterfaceStr += ((LPSTR)d->name);

		NetWorkListCtrl.SetItem(column_count, 1, LVIF_TEXT, InterfaceDescription, NULL, NULL, NULL, NULL);
		NetWorkListCtrl.SetItem(column_count, 2, LVIF_TEXT, InterfaceName, NULL, NULL, NULL, NULL);
	}

	if (column_count == 0) {
		AfxMessageBox(_T("연결된 인터페이스가 없습니다."));
		m_nSelectedIndex = -1;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 예외: OCX 속성 페이지는 FALSE를 반환해야 합니다.
}

// NetworkInterfaceDlg 메시지 처리기


void NetworkInterfaceDlg::OnBnClickedCancel() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	this->CancelButtonClicked = true;


	CDialogEx::OnCancel();
}


bool NetworkInterfaceDlg::CancelButtonClickedFunction(void) {
	return CancelButtonClicked;
}


void NetworkInterfaceDlg::OnBnClickedOk() {
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	 //value

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 1);
	InterfaceDescription = m_strSelectedValue;

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 2);
	InterfaceName = m_strSelectedValue;

	if (m_nSelectedIndex == -1) {
		MessageBox(L"Select Interface", L"Error");
		SetDlgItemText(IDC_STATIC, L"Selected nothing");
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