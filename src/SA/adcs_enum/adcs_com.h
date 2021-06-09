#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <stdint.h>





typedef struct _ADCS {
	IWbemServices* pWbemServices;
	IWbemLocator* pWbemLocator;
	IEnumWbemClassObject* pEnumerator;
	BSTR bstrLanguage;
	BSTR bstrServer;
	BSTR bstrNameSpace;
	BSTR bstrNetworkResource;
	BSTR bstrQuery;
} ADCS;

HRESULT adcs_com_Initialize(
	ADCS* pWMI
);

HRESULT adcs_com_Connect(
	ADCS* pWmi,
	LPWSTR pwszServer,
	LPWSTR pwszNameSpace	
);

HRESULT adcs_com_Query(
	ADCS* pWmi, 
	LPWSTR pwszQuery
);

HRESULT adcs_com_ParseResults(
	ADCS* pWmi,
	LPWSTR pwszKeys,
	BSTR*** ppwszResults,
	LPDWORD pdwRowCount,
	LPDWORD pdwColumnCount
);

void adcs_com_Finalize(
	ADCS* pWmi
);
