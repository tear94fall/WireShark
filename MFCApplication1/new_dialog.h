#pragma once


// new_dialog 대화 상자

class new_dialog : public CDialogEx
{
	DECLARE_DYNAMIC(new_dialog)

public:
	new_dialog(CWnd* pParent = nullptr);   // 표준 생성자입니다.
	virtual ~new_dialog();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	CListCtrl m_interfaceList;
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedCancel();
};
