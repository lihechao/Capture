
// CaptureDlg.h : ͷ�ļ�
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

#define ETHERNET_TYPE_ARP		0x0806		//ARPЭ��Ĵ���
#define ETHERNET_TYPE_IP		0x0800		//IPЭ��Ĵ���

#define IP_TYPE_ICMP			1			//ICMPЭ��Ĵ���
#define IP_TYPE_IGMP			2			//IGMPЭ��Ĵ���
#define IP_TYPE_TCP				6			//TCPЭ��Ĵ���
#define IP_TYPE_UDP				17			//UDPЭ��Ĵ���

#define MASK_SYN				0x02		//ʹSYNλ����1������
#define MASK_ACK				0x10		//ʹACKλ����1������

#define TIMEID_SYN				1
#define TIMEID_ACK				2
#define TIMEID_UDP				3
#define TIMEID_ICMP				4
#define TIMEID_PKT				5

const int NumOfButton = 11;
UINT ThreadFunc(LPVOID lpParam);		//ץ���̺߳���

// CCaptureDlg �Ի���
class CCaptureDlg : public CDialogEx
{
// ����
public:
	CCaptureDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_CAPTURE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBnClickedToolBar(UINT nID);
	DECLARE_MESSAGE_MAP()
private:
	CImageList m_imageList;	//ͼ��
	pcap_t * m_adhandle;	//�򿪵�����������	
	CWinThread* m_pThread;	//�߳�ָ��
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
	CToolBar m_toolBar;		//������
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

/* ������ʾ���ݰ�����Ϣ */
typedef struct displayitem
{
	CString	strNum;			//���
	CString strTime;		//ʱ��
	CString strProto;		//Э��
	CString strSrcIP;		//ԴIP��ַ
	CString strSrcMAC;		//ԴMAC��ַ
	CString	strSrcPort;		//Դ�˿ں�
	CString strDstIP;		//Ŀ��IP��ַ
	CString strDstMAC;		//Ŀ��MAC��ַ
	CString	strDstPort;		//Ŀ�Ķ˿ں�
	CString	strLength;		//���ݰ�����
}DisplayItem;

typedef struct eth_header //��̫������֡ͷ���ṹ
{
	u_char dhost[6];	//Ŀ��MAC��ַ
	u_char shost[6];	//ԴMAC��ַ
	u_short proto;		//�²�Э������
}eth_header;

typedef struct arp_header	//28�ֽڵ�ARPͷ
{
	u_short hrd;		//Ӳ����ַ�ռ䣬��̫����ΪARPHRD_EHER
	u_short eth_type;	//��̫�����ͣ�ETHERTYPE_IP
	u_char maclen;		//MAC��ַ�ĳ��ȣ�Ϊ6
	u_char iplen;		//IP��ַ�ĳ��ȣ�Ϊ4
	u_short opcode;		//��������
	u_char smac[6];		//ԴMAC��ַ
	u_char saddr[4];	//ԴIP��ַ
	u_char dmac[6];		//Ŀ��MAC��ַ
	u_char daddr[4];	//Ŀ��IP��ַ
}arp_header;

/* IP��ַ */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header{
    u_char  ver_ihl;        // 4���ذ汾��+4����ͷ������
    u_char  tos;            // Type of service ��������
    u_short tlen;           // �ܳ���
    u_short identification; // 
    u_short flags_fo;       // 3���ر�־λ+13���ض�ƫ��
    u_char  ttl;            // Time to live
    u_char  proto;          // Э��
    u_short crc;            // У���
    ip_address  saddr;      // Դ��ַ
    ip_address  daddr;      // Ŀ�ĵ�ַ
    u_int   op_pad;         // ѡ������
}ip_header;

/* TCP �ײ�*/
typedef struct tcp_header //20���ֽ�
{
	u_short sport;		//16λԴ�˿ں�
	u_short dport;		//16λĿ�Ķ˿ں�
	u_long	seq;		//32λ���к�
	u_long	ack;		//32λȷ�Ϻ�
	u_char	offset;		//4λ�ײ�����/4λ������
	u_char	flags;		//6λ��־λ
	u_short wnd;		//16λ���ڴ�С
	u_short checksum;	//16λУ���
	u_short urgpointer;	//16λ��������ƫ����
}tcp_header;


/* UDP �ײ�*/
typedef struct udp_header{
    u_short sport;          // Դ�˿�
    u_short dport;          // Ŀ�Ķ˿�
    u_short len;            // ���ݳ���
    u_short crc;            // У���
}udp_header;

/* ICMP �ײ�*/
typedef struct icmp_header
{
	u_char	type;		//��Ϣ����
	u_char	code;		//����
	u_short checksum;	//У���
	u_short id;			//����Ωһ��ʶ�������ID�ţ�ͨ������Ϊ����ID
	u_short sequence;	//���к�
	u_long	timestamp;	//ʱ���
}icmp_header;

/* IGMP �ײ�*/
typedef struct igmp_header //8�ֽ�
{
	u_char	ver_type;		//�汾�ź�����(��4λ)
	u_char	reserved;		//δ��
	u_short checksum;		//У���
	u_long	groupaddr;		//32λ���ַ(D��IP��ַ)
}igmp_header;