// new_dialog.cpp: 구현 파일
//

#include "pch.h"
#include "MFCApplication1.h"
#include "new_dialog.h"
#include "afxdialogex.h"


// new_dialog 대화 상자

IMPLEMENT_DYNAMIC(new_dialog, CDialogEx)

new_dialog::new_dialog(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{
}

new_dialog::~new_dialog()
{

}

void new_dialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_interfaceList);
	CRect rt;
	m_interfaceList.GetWindowRect(&rt);
	m_interfaceList.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_interfaceList.InsertColumn(0, _TEXT("Connected Interface"), LVCFMT_LEFT, rt.Width()*1);
}


BEGIN_MESSAGE_MAP(new_dialog, CDialogEx)
	ON_BN_CLICKED(IDOK, &new_dialog::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &new_dialog::OnBnClickedCancel)
END_MESSAGE_MAP()


// new_dialog 메시지 처리기


void new_dialog::OnBnClickedOk()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CDialogEx::OnOK();
}

void new_dialog::OnBnClickedCancel()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CDialogEx::OnCancel();
}
