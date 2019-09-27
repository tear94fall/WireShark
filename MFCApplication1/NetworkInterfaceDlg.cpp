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
END_MESSAGE_MAP()


BOOL NetworkInterfaceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, FALSE);			// 큰 아이콘을 설정합니다.


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

	add_column.pszText = L"Network Interface";
	add_column.cx = rt.Width() * 0.89;
	NetWorkListCtrl.InsertColumn(1, &add_column);


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

		CString netInterfaceStr;
		netInterfaceStr = ((LPSTR)d->description);
		// netInterfaceStr += ((LPSTR)d->name);
		NetWorkListCtrl.SetItem(column_count, 1, LVIF_TEXT, netInterfaceStr, NULL, NULL, NULL, NULL);
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
	CDialogEx::OnOK();
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
