#pragma once


// NetworkInterfaceDlg 대화 상자

class NetworkInterfaceDlg : public CDialogEx
{
	DECLARE_DYNAMIC(NetworkInterfaceDlg)

public:
	NetworkInterfaceDlg(CWnd* pParent = nullptr);   // 표준 생성자입니다.
	virtual ~NetworkInterfaceDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	HICON m_hIcon;
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
public:

	struct SORTPARAM
	{
		int iSrotColumn;
		bool bSortDirect;
		CListCtrl* pList;
	};


	BOOL m_bAscending;

	bool CancelButtonClicked = false;
	int m_nSelectedIndex = -123;
	CString m_strSelectedValue = L"";

	CString InterfaceName;
	CString InterfaceDescription;


	CListCtrl NetWorkListCtrl;
	afx_msg void OnBnClickedCancel();

	bool CancelButtonClickedFunction(void);
	virtual BOOL OnInitDialog();
	
	afx_msg void OnBnClickedOk();
	afx_msg void OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnHdnItemclickList1(NMHDR* pNMHDR, LRESULT* pResult);
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
