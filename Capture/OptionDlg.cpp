// OptionDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Capture.h"
#include "CaptureDlg.h"
#include "OptionDlg.h"
#include "afxdialogex.h"


// COptionDlg 对话框

IMPLEMENT_DYNAMIC(COptionDlg, CDialogEx)

COptionDlg::COptionDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(COptionDlg::IDD, pParent)
	, m_synSpeedMin(0)
	, m_synSpeedSec(1000)
	, m_ackSpeedMin(0)
	, m_ackSpeedSec(1000)
	, m_udpSpeedMin(0)
	, m_udpSpeedSec(1000)
	, m_icmpSpeedMin(0)
	, m_icmpSpeedSec(1000)
{
}

COptionDlg::~COptionDlg()
{
}

void COptionDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_SYNSPEED_MIN, m_synSpeedMin);
	DDX_Text(pDX, IDC_SYNSPEED_SEC, m_synSpeedSec);
	DDX_Text(pDX, IDC_ACKSPEED_MIN, m_ackSpeedMin);
	DDX_Text(pDX, IDC_ACKSPEED_SEC, m_ackSpeedSec);
	DDX_Text(pDX, IDC_UDPSPEED_MIN, m_udpSpeedMin);
	DDX_Text(pDX, IDC_UDPSPEED_SEC, m_udpSpeedSec);
	DDX_Text(pDX, IDC_ICMPSPEED_MIN, m_icmpSpeedMin);
	DDX_Text(pDX, IDC_ICMPSPEED_SEC, m_icmpSpeedSec);
}


BEGIN_MESSAGE_MAP(COptionDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &COptionDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &COptionDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// COptionDlg 消息处理程序


void COptionDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CCaptureDlg *pParent;
	CButton* radio;
	pParent = (CCaptureDlg *)GetParent();
	UpdateData();
	//SYN 阈值设定
	radio = (CButton *)GetDlgItem(IDC_RADIO_SYNMIN);
	if (radio -> GetCheck())
	{
		pParent -> m_bSynSpeedMin = TRUE;
		pParent -> m_synSpeed = m_synSpeedMin;
	}
	else 
	{
		pParent -> m_bSynSpeedMin = FALSE;
		pParent -> m_synSpeed = m_synSpeedSec;
	}
	//ACK阈值设定
	radio = (CButton *)GetDlgItem(IDC_RADIO_ACKMIN);
	if (radio -> GetCheck())
	{
		pParent -> m_bAckSpeedMin = TRUE;
		pParent -> m_ackSpeed = m_ackSpeedMin;
	}
	else 
	{
		pParent -> m_bAckSpeedMin = FALSE;
		pParent -> m_ackSpeed = m_ackSpeedSec;
	}
	//UDP阈值设定
	radio = (CButton *)GetDlgItem(IDC_RADIO_UDPMIN);
	if (radio -> GetCheck())
	{
		pParent -> m_bUdpSpeedMin = TRUE;
		pParent -> m_udpSpeed = m_udpSpeedMin;
	}
	else 
	{
		pParent -> m_bUdpSpeedMin = FALSE;
		pParent -> m_udpSpeed = m_udpSpeedSec;
	}
	//ICMP阈值设定
	radio = (CButton *)GetDlgItem(IDC_RADIO_ICMPMIN);
	if (radio -> GetCheck())
	{
		pParent -> m_bIcmpSpeedMin = TRUE;
		pParent -> m_icmpSpeed = m_icmpSpeedMin;
	}
	else 
	{
		pParent -> m_bIcmpSpeedMin = FALSE;
		pParent -> m_icmpSpeed = m_icmpSpeedSec;
	}
	CDialogEx::OnOK();
}



void COptionDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}


BOOL COptionDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	CButton* radio;
	radio = (CButton *)GetDlgItem(IDC_RADIO_SYNSEC);
	radio->SetCheck(1);
	radio = (CButton *)GetDlgItem(IDC_RADIO_ACKSEC);
	radio->SetCheck(1);
	radio = (CButton *)GetDlgItem(IDC_RADIO_UDPSEC);
	radio->SetCheck(1);
	radio = (CButton *)GetDlgItem(IDC_RADIO_ICMPSEC);
	radio->SetCheck(1);

	CCaptureDlg *pParent = (CCaptureDlg *)GetParent();
	m_synSpeedSec = pParent -> m_synSpeed;
	m_ackSpeedSec = pParent -> m_ackSpeed;
	m_udpSpeedSec = pParent -> m_udpSpeed;
	m_icmpSpeedSec = pParent -> m_icmpSpeed;
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}
