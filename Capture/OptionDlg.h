#pragma once


// COptionDlg �Ի���

class COptionDlg : public CDialogEx
{
	DECLARE_DYNAMIC(COptionDlg)

public:
	COptionDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~COptionDlg();
	virtual BOOL OnInitDialog();
// �Ի�������
	enum { IDD = IDD_OPTION_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

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
