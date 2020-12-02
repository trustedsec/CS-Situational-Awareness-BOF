#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <stdint.h>





typedef struct _Wmi {
	IWbemServices* pWbemServices;
	IWbemLocator* pWbemLocator;
	IEnumWbemClassObject* pEnumerator;
	BSTR bstrLanguage;
	BSTR bstrServer;
	BSTR bstrNameSpace;
	BSTR bstrNetworkResource;
	BSTR bstrQuery;
} WMI;

HRESULT Wmi_Initialize(
	WMI* pWMI
);

HRESULT Wmi_Connect(
	WMI* pWmi,
	LPWSTR pwszServer,
	LPWSTR pwszNameSpace	
);

HRESULT Wmi_Query(
	WMI* pWmi, 
	LPWSTR pwszQuery
);

HRESULT Wmi_ParseResults(
	WMI* pWmi,
	LPWSTR pwszKeys,
	BSTR*** ppwszResults,
	LPDWORD pdwRowCount,
	LPDWORD pdwColumnCount
);

void Wmi_Finalize(
	WMI* pWmi
);
