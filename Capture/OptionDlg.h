#pragma once


// COptionDlg 对话框

class COptionDlg : public CDialogEx
{
	DECLARE_DYNAMIC(COptionDlg)

public:
	COptionDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~COptionDlg();
	virtual BOOL OnInitDialog();
// 对话框数据
	enum { IDD = IDD_OPTION_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
private:
	UINT m_pktSpeedMin;
	UINT m_pktSpeedSec;
	UINT m_synSpeedMin;
	UINT m_synSpeedSec;
	UINT m_ackSpeedMin;
	UINT m_ackSpeedSec;
	UINT m_udpSpeedMin;
	UINT m_udpSpeedSec;
	UINT m_icmpSpeedMin;
	UINT m_icmpSpeedSec;
};
