#include "stdafx.h"
#include "CaptureThread.h"

extern BOOL bStop;
CCaptureThread::CCaptureThread(void)
{
}


CCaptureThread::~CCaptureThread(void)
{
}

void CCaptureThread::OnCapture(WPARAM wParam,LPARAM lParam)	//抓包线程函数
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

	//打开适配器
	if ((adhandle= pcap_open(pNICName,          // 适配器名
                              65536,            // 捕获所有数据包
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 超时时间
                              NULL,             // 不认证
                              errbuf            // 返回出错信息
                              ) ) == NULL)
    {
		MessageBox(NULL,"打开适配器出错！","错误",MB_ICONERROR);
		return;
    }
	//捕获数据包
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
		MessageBox(NULL,"读取数据包出错:："+err,"错误",MB_ICONERROR);
		return;
    }
	return;
}

BEGIN_MESSAGE_MAP(CCaptureThread, CWinThread)

	ON_THREAD_MESSAGE(WM_CAPTURE,OnCapture)

END_MESSAGE_MAP()