#include "stdafx.h"
#include "CaptureThread.h"

extern BOOL bStop;
CCaptureThread::CCaptureThread(void)
{
}


CCaptureThread::~CCaptureThread(void)
{
}

void CCaptureThread::OnCapture(WPARAM wParam,LPARAM lParam)	//ץ���̺߳���
{
	char *pNICName = (char*)wParam;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;

	//��������
	if ((adhandle= pcap_open(pNICName,          // ��������
                              65536,            // �����������ݰ�
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ʱʱ��
                              NULL,             // ����֤
                              errbuf            // ���س�����Ϣ
                              ) ) == NULL)
    {
		MessageBox(NULL,"������������","����",MB_ICONERROR);
		return;
    }
	//�������ݰ�
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 && !bStop)
	{
		if(res == 0)
            continue;
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
        
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
	
    if(res == -1){
		CString err=pcap_geterr(adhandle);
		MessageBox(NULL,"��ȡ���ݰ�����:��"+err,"����",MB_ICONERROR);
		return;
    }
	return;
}

BEGIN_MESSAGE_MAP(CCaptureThread, CWinThread)

	ON_THREAD_MESSAGE(WM_CAPTURE,OnCapture)

END_MESSAGE_MAP()