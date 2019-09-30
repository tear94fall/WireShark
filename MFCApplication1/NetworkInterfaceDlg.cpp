// NetworkInterfaceDlg.cpp: 구현 파일
//

#include "pch.h"
#include "MFCApplication1.h"
#include "NetworkInterfaceDlg.h"
#include "afxdialogex.h"

#include "pcap.h"
#include <string>

// NetworkInterfaceDlg 대화 상자

IMPLEMENT_DYNAMIC(NetworkInterfaceDlg, CDialogEx)

NetworkInterfaceDlg::NetworkInterfaceDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

NetworkInterfaceDlg::~NetworkInterfaceDlg()
{
}

void NetworkInterfaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, NetWorkListCtrl);
}


BEGIN_MESSAGE_MAP(NetworkInterfaceDlg, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &NetworkInterfaceDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDOK, &NetworkInterfaceDlg::OnBnClickedOk)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, &NetworkInterfaceDlg::OnNMClickList1)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &NetworkInterfaceDlg::OnHdnItemclickList1)
END_MESSAGE_MAP()


BOOL NetworkInterfaceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, FALSE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.

	// TODO:  여기에 추가 초기화 작업을 추가합니다.

	SetWindowText(_T("Network Interface"));


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


	pcap_if_t* alldevs;
	pcap_if_t* d;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		MessageBox(L"오류", L"다시시도 해주세요");
	}

	for (d = alldevs; d; d = d->next) {
		int column_count = NetWorkListCtrl.GetItemCount();

		CString column_count_str;
		column_count_str.Format(_T("%d"), column_count + 1);
		NetWorkListCtrl.InsertItem(column_count, column_count_str);

		InterfaceDescription = ((LPSTR)d->description);
		InterfaceName = ((LPSTR)d->name);
		// netInterfaceStr += ((LPSTR)d->name);

		NetWorkListCtrl.SetItem(column_count, 1, LVIF_TEXT, InterfaceDescription, NULL, NULL, NULL, NULL);
		NetWorkListCtrl.SetItem(column_count, 2, LVIF_TEXT, InterfaceName, NULL, NULL, NULL, NULL);
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 예외: OCX 속성 페이지는 FALSE를 반환해야 합니다.
}

// NetworkInterfaceDlg 메시지 처리기


void NetworkInterfaceDlg::OnBnClickedCancel()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	this->CancelButtonClicked = true;


	CDialogEx::OnCancel();
}


bool NetworkInterfaceDlg::CancelButtonClickedFunction(void) {
	return CancelButtonClicked;
}


void NetworkInterfaceDlg::OnBnClickedOk()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	 //value

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 1);
	InterfaceDescription = m_strSelectedValue;

	m_strSelectedValue = NetWorkListCtrl.GetItemText(m_nSelectedIndex, 2);
	InterfaceName = m_strSelectedValue;

	if (m_nSelectedIndex == -123) {
		MessageBox(L"인터페이스를 선택해주세요.", L"오류");
	}
	else {
		CDialogEx::OnOK();
	}
}


void NetworkInterfaceDlg::OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	m_nSelectedIndex = pNMListView->iItem;//


	//int idx = pNMListView -> iItem;// 선택된 아이템값의 아이템을 (0,1 ... n 번째 인덱스) 한개 가져온다.
	//CString sIndexValue;sIndexValue = m_listDataTable.GetItemText(idx, 1);
	*pResult = 0;
}


void NetworkInterfaceDlg::OnHdnItemclickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	LPNMHEADER pNMLV = reinterpret_cast<LPNMHEADER>(pNMHDR);

	int nColumn = pNMLV->iItem;
	// 선택된 헤더 숫자로 정렬해야되는 값은 0번 (No)와 5번 (Length)이다.

	for (int i = 0; i < (NetWorkListCtrl.GetItemCount()); i++) {
		NetWorkListCtrl.SetItemData(i, i);
	}
/*
	if (m_bAscending) {
		m_bAscending = false;
	}
	else {
		m_bAscending = true;
	}

	SORTPARAM sortparams;
	sortparams.pList = &NetWorkListCtrl;
	sortparams.iSrotColumn = nColumn;
	sortparams.bSortDirect = m_bAscending;

	if (nColumn == 0 || nColumn == 5) {
		NetWorkListCtrl.SortItems(&SortFuncNum, (LPARAM)& sortparams);
	}
	else {
		NetWorkListCtrl.SortItems(&SortFuncStr, (LPARAM)& sortparams);
	}*/
	*pResult = 0;
}



int CALLBACK NetworkInterfaceDlg::SortFuncStr(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
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

int CALLBACK NetworkInterfaceDlg::SortFuncNum(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
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

BOOL NetworkInterfaceDlg::PreTranslateMessage(MSG* pMsg)
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