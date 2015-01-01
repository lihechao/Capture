
// CaptureDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#define HAVE_REMOTE
#include "pcap.h"

#define ID_TOOLBUTTON 1001
#define IDC_BTN_START ID_TOOLBUTTON
#define IDC_BTN_STOP ID_TOOLBUTTON+2
#define IDC_BTN_FILTER ID_TOOLBUTTON+4
#define IDC_BTN_SAVE ID_TOOLBUTTON+6
#define IDC_BTN_HELP ID_TOOLBUTTON+8
#define IDC_BTN_EXIT ID_TOOLBUTTON+10

#define ETHERNET_TYPE_ARP		0x0806		//ARP协议的代号
#define ETHERNET_TYPE_IP		0x0800		//IP协议的代号

#define IP_TYPE_ICMP			1			//ICMP协议的代号
#define IP_TYPE_IGMP			2			//IGMP协议的代号
#define IP_TYPE_TCP				6			//TCP协议的代号
#define IP_TYPE_UDP				17			//UDP协议的代号

#define MASK_SYN				0x02		//使SYN位等于1的掩码
#define MASK_ACK				0x10		//使ACK位等于1的掩码

#define TIMEID_SYN				1
#define TIMEID_ACK				2
#define TIMEID_UDP				3
#define TIMEID_ICMP				4
#define TIMEID_PKT				5

const int NumOfButton = 11;
UINT ThreadFunc(LPVOID lpParam);		//抓包线程函数

// CCaptureDlg 对话框
class CCaptureDlg : public CDialogEx
{
// 构造
public:
	CCaptureDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CAPTURE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBnClickedToolBar(UINT nID);
	DECLARE_MESSAGE_MAP()
private:
	CImageList m_imageList;	//图像
	pcap_t * m_adhandle;	//打开的网络适配器	
	CWinThread* m_pThread;	//线程指针
	CComboBox m_comboBoxNicSelect;
	UINT m_nPacketsCnt;
	UINT m_nSYNCnt;
	UINT m_nACKCnt;
	UINT m_nUDPCnt;
	UINT m_nICMPCnt;
	UINT m_nOtherCnt;
	CListCtrl m_listWarnning;
	CString m_strPktSpeed;
public:
	CToolBar m_toolBar;		//工具条
	CString m_strNICName;
	CListCtrl m_listCtrl;
	CString m_strFilter;
	BOOL m_bSynSpeedMin;
	UINT m_synSpeed;
	BOOL m_bAckSpeedMin;
	UINT m_ackSpeed;
	BOOL m_bUdpSpeedMin;
	UINT m_udpSpeed;
	BOOL m_bIcmpSpeedMin;
	UINT m_icmpSpeed;
	CString m_strTime;

	afx_msg void OnBnClickedOk();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnIdiStart();
	afx_msg void OnIddCaptureDialog();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
};

/* 用于显示数据包的信息 */
typedef struct displayitem
{
	CString	strNum;			//序号
	CString strTime;		//时间
	CString strProto;		//协议
	CString strSrcIP;		//源IP地址
	CString strSrcMAC;		//源MAC地址
	CString	strSrcPort;		//源端口号
	CString strDstIP;		//目的IP地址
	CString strDstMAC;		//目的MAC地址
	CString	strDstPort;		//目的端口号
	CString	strLength;		//数据包长度
}DisplayItem;

typedef struct eth_header //以太网数据帧头部结构
{
	u_char dhost[6];	//目的MAC地址
	u_char shost[6];	//源MAC地址
	u_short proto;		//下层协议类型
}eth_header;

typedef struct arp_header	//28字节的ARP头
{
	u_short hrd;		//硬件地址空间，以太网中为ARPHRD_EHER
	u_short eth_type;	//以太网类型，ETHERTYPE_IP
	u_char maclen;		//MAC地址的长度，为6
	u_char iplen;		//IP地址的长度，为4
	u_short opcode;		//操作代码
	u_char smac[6];		//源MAC地址
	u_char saddr[4];	//源IP地址
	u_char dmac[6];		//目的MAC地址
	u_char daddr[4];	//目的IP地址
}arp_header;

/* IP地址 */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
    u_char  ver_ihl;        // 4比特版本号+4比特头部长度
    u_char  tos;            // Type of service 服务类型
    u_short tlen;           // 总长度
    u_short identification; // 
    u_short flags_fo;       // 3比特标志位+13比特段偏移
    u_char  ttl;            // Time to live
    u_char  proto;          // 协议
    u_short crc;            // 校验和
    ip_address  saddr;      // 源地址
    ip_address  daddr;      // 目的地址
    u_int   op_pad;         // 选项和填充
}ip_header;

/* TCP 首部*/
typedef struct tcp_header //20个字节
{
	u_short sport;		//16位源端口号
	u_short dport;		//16位目的端口号
	u_long	seq;		//32位序列号
	u_long	ack;		//32位确认号
	u_char	offset;		//4位首部长度/4位保留字
	u_char	flags;		//6位标志位
	u_short wnd;		//16位窗口大小
	u_short checksum;	//16位校验和
	u_short urgpointer;	//16位紧急数据偏移量
}tcp_header;


/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口
    u_short dport;          // 目的端口
    u_short len;            // 数据长度
    u_short crc;            // 校验和
}udp_header;

/* ICMP 首部*/
typedef struct icmp_header
{
	u_char	type;		//消息类型
	u_char	code;		//代码
	u_short checksum;	//校验和
	u_short id;			//用来惟一标识此请求的ID号，通常设置为进程ID
	u_short sequence;	//序列号
	u_long	timestamp;	//时间戳
}icmp_header;

/* IGMP 首部*/
typedef struct igmp_header //8字节
{
	u_char	ver_type;		//版本号和类型(各4位)
	u_char	reserved;		//未用
	u_short checksum;		//校验和
	u_long	groupaddr;		//32位组地址(D类IP地址)
}igmp_header;