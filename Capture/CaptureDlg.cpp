
// CaptureDlg.cpp : 实现文件
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

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

int AnalysisPacket(const u_char *pkt_data,DisplayItem &displayItem);	//分析包
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CCaptureDlg 对话框



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


// CCaptureDlg 消息处理程序

BOOL CCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	//设置工具栏
	m_imageList.Create(24,24,ILC_COLORDDB|ILC_MASK,2,0);		//创建图像列表
	m_imageList.Add(AfxGetApp()->LoadIcon( IDI_START));		//工具条图标
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

	m_toolBar.GetToolBarCtrl().SetButtonWidth(32,64);		//按钮宽度
	m_toolBar.GetToolBarCtrl().SetImageList(&m_imageList);	//设置按钮图标
	m_toolBar.SetSizes(CSize(50,50),CSize(24,24));			//
	m_toolBar.EnableToolTips(TRUE);
	m_toolBar.SetButtonText(0,"开始检测");
	m_toolBar.SetButtonText(2,"停止检测");
	m_toolBar.SetButtonText(4,"检测设置");
	m_toolBar.SetButtonText(6,"保存结果");
	m_toolBar.SetButtonText(8,"帮助");
	m_toolBar.SetButtonText(10,"退出");
	m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//开始时不能按停止

	RepositionBars(AFX_IDW_CONTROLBAR_FIRST,AFX_IDW_CONTROLBAR_LAST,0);	//放置工具栏
	
	m_listCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);	//可以选中一行
	//设置结果列表的表头
	m_listCtrl.InsertColumn(0,"序号", LVCFMT_CENTER, 40, 0);
	m_listCtrl.InsertColumn(1,"时间", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(2,"协议", LVCFMT_CENTER, 50, 0);
	m_listCtrl.InsertColumn(3,"源IP地址", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(4,"源MAC地址", LVCFMT_CENTER, 150, 0);
	m_listCtrl.InsertColumn(5,"源端口", LVCFMT_CENTER, 60, 0);
	m_listCtrl.InsertColumn(6,"目的IP地址", LVCFMT_CENTER, 120, 0);
	m_listCtrl.InsertColumn(7,"目的MAC地址", LVCFMT_CENTER, 150, 0);
	m_listCtrl.InsertColumn(8,"目的端口", LVCFMT_CENTER, 60, 0);
	m_listCtrl.InsertColumn(9,"长度", LVCFMT_CENTER, 50, 0);

	m_listWarnning.InsertColumn(1,"警告信息", LVCFMT_CENTER,968);

	//设置网卡

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	pAdapterInfo = new IP_ADAPTER_INFO[sizeof(IP_ADAPTER_INFO)];
	ULONG ulOutbufLen = sizeof(IP_ADAPTER_INFO);
	if ( ERROR_BUFFER_OVERFLOW == GetAdaptersInfo( pAdapterInfo, &ulOutbufLen) )	//获取网卡信息发生溢出
	{
		free(pAdapterInfo);
		pAdapterInfo = new IP_ADAPTER_INFO[ulOutbufLen];	//重新分配合适大小的空间
	}
	if ( NO_ERROR == GetAdaptersInfo( pAdapterInfo, &ulOutbufLen ))
	{
		pAdapter = pAdapterInfo;
		if (pAdapterInfo == NULL)
		{
			MessageBox("没有找到网络适配器！","提示",MB_ICONWARNING);
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
		MessageBox("获取网络适配器列表出错！","错误",MB_ICONERROR);
	}
	delete pAdapterInfo;
	m_comboBoxNicSelect.SetCurSel(0);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCaptureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCaptureDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
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
        // 设置背景为白色 
        pDC->SetBkColor(RGB(255,255,255));
        // 设置文字为黑色
        pDC->SetTextColor(RGB(0,0, 0));
        // 返回白色画刷
        return (HBRUSH)GetStockObject(WHITE_BRUSH);
    }
	return hbr;
}


void CCaptureDlg::OnBnClickedToolBar(UINT nID)		//响应工具条按钮
{
	COptionDlg optDlg;
	switch (nID)
	{
	case IDC_BTN_START:
		bStop = 0;
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,FALSE);	//开始键按下后不能再按
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,TRUE);	//开始键按下后停止键可以按
		m_listCtrl.DeleteAllItems();
		m_listWarnning.DeleteAllItems();
		GetDlgItem(IDC_NICSELECT) -> GetWindowTextA(m_strNICName);	//所选网络适配器信息
		m_strNICName = "\\Device\\NPF_"+m_strNICName.Mid(m_strNICName.Find("{"));	//所选的网络适配器名

		SetTimer(TIMEID_PKT,1000,0);
		SetTimer(TIMEID_SYN,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_ACK,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_UDP,m_bUdpSpeedMin ? 60000 : 1000,0);
		SetTimer(TIMEID_ICMP,m_bUdpSpeedMin ? 60000 : 1000,0);
		

		
		packetsCnt = 0;		//统计信息清空
		synCnt = 0;
		ackCnt = 0;
		udpCnt = 0;
		icmpCnt = 0;
		otherCnt = 0;
		m_strTime = "";
		m_pThread=AfxBeginThread(ThreadFunc, (LPVOID)this);		//开启抓包线程
		start = GetTickCount();
		UpdateData(FALSE);
		break;
	case IDC_BTN_STOP:
		bStop = 1;	//停止抓包
		KillTimer(TIMEID_UDP);
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);	//开始键可以再按
		m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//停止键不可以按
/*		m_nPacketsCnt = packetsCnt;
		m_nSYNCnt = synCnt;
		m_nACKCnt = ackCnt;
		m_nUDPCnt = udpCnt;
		m_nICMPCnt = icmpCnt;
		m_nOtherCnt = otherCnt;
		DWORD min,sec,millsec;
		min = (end - start)/1000/60;	//分钟
		sec = (end - start - min*60*1000)/1000;	//秒
		millsec = end - start - sec *1000;	//毫秒
		m_strTime.Format("%d分%d秒%d毫秒",min,sec,millsec);
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
		if (IDYES == MessageBox("是否退出？","提示",MB_ICONQUESTION|MB_YESNO))
		{
			CCaptureDlg::OnCancel();
		}
		break;
	default:
		break;
	}
}


UINT ThreadFunc(LPVOID lpParam)		//抓包线程函数
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


	//打开适配器
	if ((adhandle= pcap_open(pCaptureDlg -> m_strNICName,        // 适配器名
                              65536,            // 捕获所有数据包
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 超时时间
                              NULL,             // 不认证
                              errbuf            // 返回出错信息
                              ) ) == NULL)
    {
		MessageBox(NULL,"打开适配器出错！","错误",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);	//开始键可以再按
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);	//停止键不可以按
		return 1;
    }
	
	/* 只支持以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
		MessageBox(NULL,"目前只支持以太网！","错误",MB_ICONERROR);
        return 1;
    }
	
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
		MessageBox(NULL,"获取网络适配器信息错误","错误",MB_ICONERROR);
        return 1;
    }
    
    for(d=alldevs; d; d=d->next)	//定位到指定网络适配器
    {
		if (pCaptureDlg -> m_strNICName == d->name)
		{
			break;
		}
    }

	if(d->addresses != NULL)
        /* 获取适配器的掩码信息 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 默认C类地址 */
        netmask=0xffffff; 
	pcap_freealldevs(alldevs);
    
	//编译过滤规则
    if (pcap_compile(adhandle, &fcode, pCaptureDlg -> m_strFilter, 1, netmask) <0 )
    {
		MessageBox(NULL,"过滤表达式语法错误！","错误",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,TRUE);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,FALSE);
        return 1;
    }
    //设置过滤规则
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
		MessageBox(NULL,"过滤条件设置失败！","错误",MB_ICONERROR);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_START,FALSE);
		pCaptureDlg -> m_toolBar.GetToolBarCtrl().EnableButton(IDC_BTN_STOP,TRUE);
        return 1;
    }

	//捕获数据包
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 && !bStop)
	{
		if(res == 0)
            continue;
		if (AnalysisPacket(pkt_data,displayItem) >= 0)
		{
			local_tv_sec = header->ts.tv_sec;		//时间
			localtime_s(&ltime, &local_tv_sec);
			strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
			displayItem.strNum.Format("%d",packetsCnt);		//序号
			displayItem.strTime.Format("%s.%.6d", timestr, header->ts.tv_usec);	//时间
			displayItem.strLength.Format("%d",header->len);		//包长度
			int nIndex = pCaptureDlg -> m_listCtrl.GetItemCount();	//新插入行的索引

			//在列表显示
			pCaptureDlg -> m_listCtrl.InsertItem(nIndex,displayItem.strNum);		//序号
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,1,displayItem.strTime);	//时间
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,2,displayItem.strProto);	//协议
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,3,displayItem.strSrcIP);	//源IP
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,4,displayItem.strSrcMAC);	//源MAC
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,5,displayItem.strSrcPort);	//源端口
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,6,displayItem.strDstIP);	//目的IP
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,7,displayItem.strDstMAC);	//目的MAC
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,8,displayItem.strDstPort);	//目的端口
			pCaptureDlg -> m_listCtrl.SetItemText(nIndex,9,displayItem.strLength);	//长度

		}
    }
    if(res == -1){
		CString err=pcap_geterr(adhandle);
		MessageBox(NULL,"读取数据包出错:："+err,"错误",MB_ICONERROR);
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
		eth->shost[2],eth->shost[3],eth->shost[4],eth->shost[5]);	//源MAC
	displayItem.strDstMAC.Format("%02x:%02x:%02x:%02x:%02x:%02x",eth->dhost[0],eth->dhost[1],
		eth->dhost[2],eth->dhost[3],eth->dhost[4],eth->dhost[5]);	//目的MAC
	displayItem.strProto = "OTHER";
	displayItem.strSrcIP = "";
	displayItem.strDstIP = "";
	displayItem.strSrcPort = "";
	displayItem.strDstPort = "";
	if (ETHERNET_TYPE_ARP == ntohs(eth -> proto))		//ARP协议
	{
		displayItem.strProto = "ARP";
	}
	else if (ETHERNET_TYPE_IP == ntohs(eth -> proto))		//IP协议
	{
		 /* 获取IP首部的位置 */
		ih = (ip_header *) (pkt_data +14); //14是以太首部的长度
		ip_len = (ih->ver_ihl & 0xf) * 4;	//IP头部长度
		displayItem.strSrcIP.Format("%d.%d.%d.%d",ih->saddr.byte1,
			ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
        displayItem.strDstIP.Format("%d.%d.%d.%d",ih->daddr.byte1,
			ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
		switch(ih -> proto)
		{
		case IP_TYPE_TCP:		//TCP包
			displayItem.strProto = "TCP";

			/* 获取TCP首部的位置 */
			th = (tcp_header *) ((u_char*)ih + ip_len);

			/* 网络字节序转成主机字节序 */
			sport = ntohs( th->sport );
			dport = ntohs( th->dport );
			displayItem.strSrcPort.Format("%d",sport);	//源端口
			displayItem.strDstPort.Format("%d",dport);	//目的端口
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
		case IP_TYPE_UDP:		//UDP包

			displayItem.strProto = "UDP";

			/* 获取UDP首部的位置 */
			uh = (udp_header *) ((u_char*)ih + ip_len);

			/* 网络字节序转成主机字节序 */
			sport = ntohs( uh->sport );
			dport = ntohs( uh->dport );
			displayItem.strSrcPort.Format("%d",sport);	//源端口
			displayItem.strDstPort.Format("%d",dport);	//目的端口

			udpCnt ++;
			udpNewSpeed ++;
			break;
		case IP_TYPE_ICMP:		//ICMP包
			displayItem.strProto = "ICMP";
			icmpCnt ++;
			icmpNewSpeed ++;
			break;
		case IP_TYPE_IGMP:		//IGMP包
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
	packetsCnt ++;	//总包数+1
	pktNewSpeed ++;	
	return 0;
}



void CCaptureDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	switch(nIDEvent)
	{
	case TIMEID_SYN:
//		synSpeed = 0 == synSpeed ? synNewSpeed : (UINT)((1-alph) * synSpeed + alph * synNewSpeed);
		synSpeed = synNewSpeed;
		if (synSpeed > m_synSpeed)
		{
			CString strDate,strTime,strWarnning;
			CTime time = CTime::GetCurrentTime();///构造CTime对象　
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  SYN包超过阈值！可能正遭受SYN Flood攻击！");
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
			CTime time = CTime::GetCurrentTime();///构造CTime对象　
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  ACK包超过阈值！可能正遭受ACK Flood攻击！");
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
			CTime time = CTime::GetCurrentTime();///构造CTime对象　
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  UDP包超过阈值！可能正遭受UDP Flood攻击！");
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
			CTime time = CTime::GetCurrentTime();///构造CTime对象　
			strWarnning = time.Format("%Y-%m-%d %H:%M:%S  ICMP包超过阈值！可能正遭受ICMP Flood攻击！");
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
			min = (end - start)/1000/60;	//分钟
			sec = (end - start - min*60*1000)/1000;	//秒
			millsec = end - start - sec *1000;	//毫秒
			m_strTime.Format("%d分%d秒%d毫秒",min,sec,millsec);

			pktSpeed = 0 == pktSpeed ? pktNewSpeed : (UINT)((1-alph) * pktSpeed + alph * pktNewSpeed);
//			pktSpeed = pktNewSpeed;
			pktNewSpeed = 0;
			m_strPktSpeed.Format("%d 个/秒", pktSpeed);

			UpdateData(FALSE);
		}
		break;
    default:
        ;
    }
	CDialogEx::OnTimer(nIDEvent);
}
