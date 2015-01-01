#pragma once
#include "afxwin.h"

#define HAVE_REMOTE
#include "pcap.h"

#define WM_CAPTURE WM_USER+1

class CCaptureThread :
	public CWinThread
{
public:
	CCaptureThread(void);
	~CCaptureThread(void);
protected:
	afx_msg void OnCapture(WPARAM wParam,LPARAM lParam);
	DECLARE_MESSAGE_MAP()
};

