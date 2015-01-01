
// CaptureDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "Capture.h"
#include "CaptureDlg.h"
#include "afxdialogex.h"
#include "OptionDlg.h"
#include<winsock2.h>
#include<iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BOOL bStop = 0;
UINT packetsCnt = 0;
UINT synCnt = 0;
UINT ackCnt = 0;
UINT udpCnt = 0;
UINT icmpCnt = 0;
UINT otherCnt = 0;
DWORD  start = 0, end = 0;

UINT synSpeed = 0,synNewSpeed = 0;
UINT ackSpeed = 0,ackNewSpeed = 0;
UINT udpSpeed = 0,udpNewSpeed = 0;
UINT icmpSpeed = 0,icmpNewSpeed = 0;
UINT pktSpeed = 0,pktNewSpeed = 0;

static const float alph = 0.5;

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

int AnalysisPacket(const u_char *pkt_data,DisplayItem &displayItem);	//������
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CCaptureDlg �Ի���



CCaptureDlg::CCaptureDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCaptureDlg::IDD, pParent)
	, m_strNICName(_T(""))
	, m_nPacketsCnt(0)
	, m_nSYNCnt(0)
	, m_nACKCnt(0)
	, m_nUDPCnt(0)
	, m_nICMPCnt(0)
	, m_nOtherCnt(0)
	, m_strTime(_T(""))
	, m_bUdpSpeedMin(FALSE)
	, m_synSpeed(1000)
	, m_ackSpeed(1000)
	, m_udpSpeed(1000)
	, m_icmpSpeed(1000)
	, m_strPktSpeed(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCaptureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_listCtrl);
	DDX_Control(pDX, IDC_NICSELECT, m_comboBoxNicSelect);
	DDX_CBString(pDX, IDC_NICSELECT, m_strNICName);
	DDX_Text(pDX, IDC_PACKETSCNT, m_nPacketsCnt);
	DDX_Text(pDX, IDC_SYNCNT, m_nSYNCnt);
	DDX_Text(pDX, IDC_ACKCNT, m_nACKCnt);
	DDX_Text(pDX, IDC_UDPCNT, m_nUDPCnt);
	DDX_Text(pDX, IDC_ICMPCNT, m_nICMPCnt);
	DDX_Text(pDX, IDC_OTHERCNT, m_nOtherCnt);
	DDX_Text(pDX, IDC_TIME, m_strTime);
	DDX_Control(pDX, IDC_LIST_WARNNING, m_listWarnning);
	DDX_Text(pDX, IDC_SPEED, m_strPktSpeed);
}

BEGIN_MESSAGE_MAP(CCaptureDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CCaptureDlg::OnBnClickedOk)
	ON_WM_CTLCOLOR()
	ON_COMMAND_RANGE(ID_TOOLBUTTON,ID_TOOLBUTTON+NumOfButton,OnBnClickedToolBar)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CCaptureDlg ��Ϣ�������

BOOL CCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	//���ù�����
	m_imageList.Create(24,24,ILC_COLORDDB|ILC_MASK,2,0);		//����ͼ���б�
	m_imageList.Add(AfxGetApp()->LoadIcon( IDI_START));		//������ͼ��
	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_STOP));
//	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_SETTING));
	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_FILTER));
	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_SAVE));
	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_HELP));
	m_imageList.Add(AfxGetApp()->LoadIcon(IDI_EXIT));

	UINT array[NumOfButton];
	for (int i = 0;i<NumOfButton;i++)
	{
		array[i]=i%2?ID_SEPARATOR:i+ID_TOOLBUTTON;
	}

	m_toolBar.Create(this);
	m_toolBar.SetButtons(array,NumOfButton);  

	m_toolBar.GetToolBarCtrl().SetButtonWidth(32,64);		//��ť���
	m_toolBar.GetToolBarCtrl().SetImageList(&m_imageList);	//���ð�ťͼ��
	m_toolBar.SetSizes(CSize(50,50),CSize(24,24));			//
	m_toolBar.EnableToolTips(TRUE);
	m_toolBar.SetButtonText(0,"��ʼ���");
	m_toolBar.SetButtonText(2,"ֹͣ���");
	m_toolBar.SetButtonText(4,"�������");
	m_toolBar.SetButtonText(6,"������");
	m_toolBar.SetButtonText(8,"����");
	m_toolBar.SetButtonText(10,"�˳�");
	m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//��ʼʱ���ܰ�ֹͣ

	RepositionBars(AFX_IDW_CONTROLBAR_FIRST,AFX_IDW_CONTROLBAR_LAST,0);	//���ù�����
	
	m_listCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);	//����ѡ��һ��
	//���ý���б�ı�ͷ
	m_listCtrl.InsertColumn(0,"���", LVCFMT_CENTER, 40, 0);
	m_listCtrl.InsertColumn(1,"ʱ��", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(2,"Э��", LVCFMT_CENTER, 50, 0);
	m_listCtrl.InsertColumn(3,"ԴIP��ַ", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(4,"ԴMAC��ַ", LVCFMT_CENTER, 150, 0);
	m_listCtrl.InsertColumn(5,"Դ�˿�", LVCFMT_CENTER, 60, 0);
	m_listCtrl.InsertColumn(6,"Ŀ��IP��ַ", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(7,"Ŀ��MAC��ַ", LVCFMT_CENTER, 150, 0);
	m_listCtrl.InsertColumn(8,"Ŀ�Ķ˿�", LVCFMT_CENTER, 60, 0);
	m_listCtrl.InsertColumn(9,"����", LVCFMT_CENTER, 50, 0);

	m_listWarnning.InsertColumn(1,"������Ϣ", LVCFMT_CENTER,968);

	//��������

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	pAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
	ULONG ulOutbufLen = sizeof(IP_ADAPTER_INFO);
	if ( ERROR_BUFFER_OVERFLOW == GetAdaptersInfo( pAdapterInfo, &ulOutbufLen) )	//��ȡ������Ϣ�������
	{
		free(pAdapterInfo);
		pAdapterInfo = new IP_ADAPTER_INFO[ulOutbufLen];	//���·�����ʴ�С�Ŀռ�
	}
	if ( NO_ERROR == GetAdaptersInfo( pAdapterInfo, &ulOutbufLen ))
	{
		pAdapter = pAdapterInfo;
		if (pAdapterInfo == NULL)
		{
			MessageBox("û���ҵ�������������","��ʾ",MB_ICONWARNING);
		}
		for (pAdapter = pAdapter; pAdapter != NULL;    pAdapter = pAdapter->Next) 
		{
			CString strInfo = pAdapter -> Description;
			strInfo = strInfo + ": "+ (pAdapter -> AdapterName);
			m_comboBoxNicSelect.AddString(strInfo);
		}
	}
	else 
	{
		MessageBox("��ȡ�����������б����","����",MB_ICONERROR);
	}
	delete pAdapterInfo;
	m_comboBoxNicSelect.SetCurSel(0);
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CCaptureDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CCaptureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCaptureDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
//	CDialogEx::OnOK();
}


HBRUSH CCaptureDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

	if (pWnd->GetDlgCtrlID() == IDC_PACKETSCNT ||
		pWnd->GetDlgCtrlID() == IDC_ARPCNT ||
		pWnd->GetDlgCtrlID() == IDC_TCPCNT ||
		pWnd->GetDlgCtrlID() == IDC_UDPCNT ||
		pWnd->GetDlgCtrlID() == IDC_ICMPCNT ||
		pWnd->GetDlgCtrlID() == IDC_IGMPCNT ||
		pWnd->GetDlgCtrlID() == IDC_OTHERCNT ||
		pWnd->GetDlgCtrlID() == IDC_TIME ||
		pWnd->GetDlgCtrlID() == IDC_DATADETAIL)
    {
        // ���ñ���Ϊ��ɫ 
        pDC->SetBkColor(RGB(255,255,255));
        // ��������Ϊ��ɫ
        pDC->SetTextColor(RGB(0,0, 0));
        // ���ذ�ɫ��ˢ
        return (HBRUSH)GetStockObject(WHITE_BRUSH);
    }
	return hbr;
}


void CCaptureDlg::OnBnClickedToolBar(UINT nID)		//��Ӧ��������ť
{
	COptionDlg optDlg;
	switch (nID)
	{
	case IDC_BTN_START:
		bStop = 0;
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,FALSE);	//��ʼ�����º����ٰ�
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,TRUE);	//��ʼ�����º�ֹͣ�����԰�
		m_listCtrl.DeleteAllItems();
		m_listWarnning.DeleteAllItems();
		GetDlgItem(IDC_NICSELECT) -> GetWindowTextA(m_strNICName);	//��ѡ������������Ϣ
		m_strNICName = "\\Device\\NPF_"+m_strNICName.Mid(m_strNICName.Find("{"));	//��ѡ��������������

		SetTimer(TIMEID_PKT,1000,0);
		SetTimer(TIMEID_SYN,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_ACK,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_UDP,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_ICMP,m_bUdpSpeedMin ? 60000 : 1000,0);
		

		
		packetsCnt = 0;		//ͳ����Ϣ���
		synCnt = 0;
		ackCnt = 0;
		udpCnt = 0;
		icmpCnt = 0;
		otherCnt = 0;
		m_strTime = "";
		m_pThread=AfxBeginThread(ThreadFunc, (LPVOID)this);		//����ץ���߳�
		start = GetTickCount();
		UpdateData(FALSE);
		break;
	case IDC_BTN_STOP:
		bStop = 1;	//ֹͣץ��
		KillTimer(TIMEID_UDP);
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);	//��ʼ�������ٰ�
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//ֹͣ�������԰�
/*		m_nPacketsCnt = packetsCnt;
		m_nSYNCnt = synCnt;
		m_nACKCnt = ackCnt;
		m_nUDPCnt = udpCnt;
		m_nICMPCnt = icmpCnt;
		m_nOtherCnt = otherCnt;
		DWORD min,sec,millsec;
		min = (end - start)/1000/60;	//����
		sec = (end - start - min*60*1000)/1000;	//��
		millsec = end - start - sec *1000;	//����
		m_strTime.Format("%d��%d��%d����",min,sec,millsec);
		UpdateData(FALSE);*/
		KillTimer(TIMEID_SYN);
		KillTimer(TIMEID_ACK);
		KillTimer(TIMEID_UDP);
		KillTimer(TIMEID_ICMP);
		KillTimer(TIMEID_PKT);
		break;
	case IDC_BTN_FILTER:
		optDlg.DoModal();
		break;
	case IDC_BTN_SAVE:
		break;
	case IDC_BTN_HELP:
		break;
	case IDC_BTN_EXIT:
		if (IDYES == MessageBox("�Ƿ��˳���","��ʾ",MB_ICONQUESTION|MB_YESNO))
		{
			CCaptureDlg::OnCancel();
		}
		break;
	default:
		break;
	}
}


UINT ThreadFunc(LPVOID lpParam)		//ץ���̺߳���
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	CCaptureDlg *pCaptureDlg = (CCaptureDlg *)lpParam;
	DisplayItem displayItem;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	CString strProto;
	u_int netmask;
	struct bpf_program fcode;


	//��������
	if ((adhandle= pcap_open(pCaptureDlg -> m_strNICName,        // ��������
                              65536,            // �����������ݰ�
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ʱʱ��
                              NULL,             // ����֤
                              errbuf            // ���س�����Ϣ
                              ) ) == NULL)
    {
		MessageBox(NULL,"������������","����",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);	//��ʼ�������ٰ�
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//ֹͣ�������԰�
		return 1;
    }
	
	/* ֻ֧����̫�� */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
		MessageBox(NULL,"Ŀǰֻ֧����̫����","����",MB_ICONERROR);
        return 1;
    }
	
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
		MessageBox(NULL,"��ȡ������������Ϣ����","����",MB_ICONERROR);
        return 1;
    }
    
    for(d=alldevs; d; d=d->next)	//��λ��ָ������������
    {
		if (pCaptureDlg -> m_strNICName == d->name)
		{
			break;
		}
    }

	if(d->addresses != NULL)
        /* ��ȡ��������������Ϣ */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* Ĭ��C���ַ */
        netmask=0xffffff; 
	pcap_freealldevs(alldevs);
    
	//������˹���
    if (pcap_compile(adhandle, &fcode, pCaptureDlg -> m_strFilter, 1, netmask) <0 )
    {
		MessageBox(NULL,"���˱��ʽ�﷨����","����",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);
        return 1;
    }
    //���ù��˹���
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
		MessageBox(NULL,"������������ʧ�ܣ�","����",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,FALSE);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,TRUE);
        return 1;
    }

	//�������ݰ�
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 && !bStop)
	{
		if(res == 0)
            continue;
		if (AnalysisPacket(pkt_data,displayItem) >= 0)
		{
			local_tv_sec = header->ts.tv_sec;		//ʱ��
			localtime_s(&ltime, &local_tv_sec);
			strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
			displayItem.strNum.Format("%d",packetsCnt);		//���
			displayItem.strTime.Format("%s.%.6d", timestr, header->ts.tv_usec);	//ʱ��
			displayItem.strLength.Format("%d",header->len);		//������
			int nIndex = pCaptureDlg -> m_listCtrl.GetItemCount();	//�²����е�����

			//���б���ʾ
			pCaptureDlg -> m_listCtrl.InsertItem(nIndex,displayItem.strNum);		//���
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,1,displayItem.strTime);	//ʱ��
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,2,displayItem.strProto);	//Э��
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,3,displayItem.strSrcIP);	//ԴIP
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,4,displayItem.strSrcMAC);	//ԴMAC
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,5,displayItem.strSrcPort);	//Դ�˿�
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,6,displayItem.strDstIP);	//Ŀ��IP
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,7,displayItem.strDstMAC);	//Ŀ��MAC
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,8,displayItem.strDstPort);	//Ŀ�Ķ˿�
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,9,displayItem.strLength);	//����

		}
    }
    if(res == -1){
		CString err=pcap_geterr(adhandle);
		MessageBox(NULL,"��ȡ���ݰ�����:��"+err,"����",MB_ICONERROR);
		return 1;
    }
	return 0;
}

int AnalysisPacket(const u_char *pkt_data,DisplayItem &displayItem)
{
	eth_header *eth;
	ip_header *ih;
	tcp_header *th;
	udp_header *uh;
	u_int ip_len;
	u_short sport = 0,dport = 0;
	eth = (eth_header *) pkt_data;
	displayItem.strSrcMAC.Format("%02x:%02x:%02x:%02x:%02x:%02x",eth->shost[0],eth->shost[1],
		eth->shost[2],eth->shost[3],eth->shost[4],eth->shost[5]);	//ԴMAC
	displayItem.strDstMAC.Format("%02x:%02x:%02x:%02x:%02x:%02x",eth->dhost[0],eth->dhost[1],
		eth->dhost[2],eth->dhost[3],eth->dhost[4],eth->dhost[5]);	//Ŀ��MAC
	displayItem.strProto = "OTHER";
	displayItem.strSrcIP = "";
	displayItem.strDstIP = "";
	displayItem.strSrcPort = "";
	displayItem.strDstPort = "";
	if (ETHERNET_TYPE_ARP == ntohs(eth -> proto))		//ARPЭ��
	{
		displayItem.strProto = "ARP";
	}
	else if (ETHERNET_TYPE_IP == ntohs(eth -> proto))		//IPЭ��
	{
		 /* ��ȡIP�ײ���λ�� */
		ih = (ip_header *) (pkt_data +14); //14����̫�ײ��ĳ���
		ip_len = (ih->ver_ihl & 0xf) * 4;	//IPͷ������
		displayItem.strSrcIP.Format("%d.%d.%d.%d",ih->saddr.byte1,
			ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
        displayItem.strDstIP.Format("%d.%d.%d.%d",ih->daddr.byte1,
			ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
		switch(ih -> proto)
		{
		case IP_TYPE_TCP:		//TCP��
			displayItem.strProto = "TCP";

			/* ��ȡTCP�ײ���λ�� */
			th = (tcp_header *) ((u_char*)ih + ip_len);

			/* �����ֽ���ת�������ֽ��� */
			sport = ntohs( th->sport );
			dport = ntohs( th->dport );
			displayItem.strSrcPort.Format("%d",sport);	//Դ�˿�
			displayItem.strDstPort.Format("%d",dport);	//Ŀ�Ķ˿�
			if (th -> flags & MASK_SYN)
			{
				synCnt ++;
				synNewSpeed ++;
				displayItem.strProto = "SYN";
			}
			if (th -> flags & MASK_ACK)
			{
				ackCnt ++;
				ackNewSpeed ++;
				displayItem.strProto = "ACK";
			}
			break;
		case IP_TYPE_UDP:		//UDP��

			displayItem.strProto = "UDP";

			/* ��ȡUDP�ײ���λ�� */
			uh = (udp_header *) ((u_char*)ih + ip_len);

			/* �����ֽ���ת�������ֽ��� */
			sport = ntohs( uh->sport );
			dport = ntohs( uh->dport );
			displayItem.strSrcPort.Format("%d",sport);	//Դ�˿�
			displayItem.strDstPort.Format("%d",dport);	//Ŀ�Ķ˿�

			udpCnt ++;
			udpNewSpeed ++;
			break;
		case IP_TYPE_ICMP:		//ICMP��
			displayItem.strProto = "ICMP";
			icmpCnt ++;
			icmpNewSpeed ++;
			break;
		case IP_TYPE_IGMP:		//IGMP��
			displayItem.strProto = "IGMP";
			otherCnt ++;
			break;
		default:
			otherCnt ++;
			break;
		}
	}
	else 
		return -1;
	packetsCnt ++;	//�ܰ���+1
	pktNewSpeed ++;	
	return 0;
}



void CCaptureDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ

	switch(nIDEvent)
	{
	case TIMEID_SYN:
//		synSpeed = 0 == synSpeed ? synNewSpeed : (UINT)((1-alph) * synSpeed + alph * synNewSpeed);
		synSpeed = synNewSpeed;
		if (synSpeed > m_synSpeed)
		{
			CString strDate,strTime,strWarnning;
			CTime time = CTime::GetCurrentTime();///����CTime����
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  SYN��������ֵ������������SYN Flood������");
			m_listWarnning.InsertItem(m_listWarnning.GetItemCount(),strWarnning);	
		}
		synNewSpeed = 0;
		break;
	case TIMEID_ACK:
//		ackSpeed = 0 == ackSpeed ? synNewSpeed : (UINT)((1-alph) * ackSpeed + alph * ackNewSpeed);
		ackSpeed = ackNewSpeed;
		if (ackSpeed > m_ackSpeed)
		{
			CString strDate,strTime,strWarnning;
			CTime time = CTime::GetCurrentTime();///����CTime����
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  ACK��������ֵ������������ACK Flood������");
			m_listWarnning.InsertItem(m_listWarnning.GetItemCount(),strWarnning);	
		}
		synNewSpeed = 0;
		break;
	case TIMEID_UDP:
//		udpSpeed = 0 == udpSpeed ? udpNewSpeed : (UINT)((1-alph) * udpSpeed + alph * udpNewSpeed);
		udpSpeed = udpNewSpeed;
		if (udpSpeed > m_udpSpeed)
		{
			CString strDate,strTime,strWarnning;
			CTime time = CTime::GetCurrentTime();///����CTime����
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  UDP��������ֵ������������UDP Flood������");
			m_listWarnning.InsertItem(m_listWarnning.GetItemCount(),strWarnning);	
		}
		udpNewSpeed = 0;
		break;
	case TIMEID_ICMP:
//		icmpSpeed = 0 == icmpSpeed ? icmpNewSpeed : (UINT)((1-alph) * icmpSpeed + alph * icmpNewSpeed);
		icmpSpeed = icmpNewSpeed;
		if (icmpSpeed > m_icmpSpeed)
		{
			CString strDate,strTime,strWarnning;
			CTime time = CTime::GetCurrentTime();///����CTime����
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  ICMP��������ֵ������������ICMP Flood������");
			m_listWarnning.InsertItem(m_listWarnning.GetItemCount(),strWarnning);	
		}
		icmpNewSpeed = 0;

		break;
	case TIMEID_PKT:
		{
			DWORD min,sec,millsec;
			end = GetTickCount();
			m_nPacketsCnt = packetsCnt;
			m_nSYNCnt = synCnt;
			m_nACKCnt = ackCnt;
			m_nUDPCnt = udpCnt;
			m_nICMPCnt = icmpCnt;
			m_nOtherCnt = otherCnt;
			min = (end - start)/1000/60;	//����
			sec = (end - start - min*60*1000)/1000;	//��
			millsec = end - start - sec *1000;	//����
			m_strTime.Format("%d��%d��%d����",min,sec,millsec);

			pktSpeed = 0 == pktSpeed ? pktNewSpeed : (UINT)((1-alph) * pktSpeed + alph * pktNewSpeed);
//			pktSpeed = pktNewSpeed;
			pktNewSpeed = 0;
			m_strPktSpeed.Format("%d ��/��", pktSpeed);

			UpdateData(FALSE);
		}
		break;
    default:
        ;
    }
	CDialogEx::OnTimer(nIDEvent);
}
