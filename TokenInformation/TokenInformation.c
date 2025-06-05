#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include <stdio.h>
#include <Lmcons.h>

HANDLE pHandle = NULL;
HANDLE tokenH = NULL;

BOOL prog = FALSE;

char* buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
DWORD ulen = MAXIMUM_REPARSE_DATA_BUFFER_SIZE;

#define _DEBUG 0

int main() {
	pHandle = GetCurrentProcess();
	if (pHandle == NULL) {
		printf("Handle to the current process' token could not be obtained.\n 0x%p\n", GetLastError());
		return 1;
	}

	OpenProcessToken(pHandle, TOKEN_READ, &tokenH);
	
	// Token User
	char* pSidStr = NULL;
	char uname[256];
	DWORD szUname = 256;
	char userInfo[1024];

	GetUserNameA(uname, &szUname);

	GetTokenInformation(tokenH,TokenUser, (LPVOID)buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &ulen);
	PTOKEN_USER pUserInfo = (PTOKEN_USER)buffer;
	if (pUserInfo == NULL) {
		printf("User information could not be obtained.");
		return 1;
	}
	else {
		ConvertSidToStringSidA(pUserInfo->User.Sid, &pSidStr);
		sprintf_s(userInfo,1024,"Username:%s \nSID of the user: %s\n\n",uname,pSidStr);
	}
	printf("%s", userInfo);

	// Token Groups
	GetTokenInformation(tokenH, TokenGroups, (LPVOID)buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &ulen);
	PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)buffer;
	if (pGroupInfo == NULL) {
		printf("Group Information could not be fetched.\n0x%p", GetLastError());
		return 1;
	}
	else {
		printf("The total Groups Privileges of the current process are: %d\n\n", pGroupInfo->GroupCount);
	}

	#if !_DEBUG
	printf("Unique Groups:\n");
	#endif
	char allGroups[16384] = { 0 };
	for (int index = 0;index < pGroupInfo->GroupCount;index++) {
		char GroupName[1024] = { 0 };
		char DomainName[1024] = { 0 };
		PSID psid;
		char* sidString = NULL;
		DWORD groupsize ;
		DWORD domainsize ;
		SID_NAME_USE sidtype;
		SID sid;
		
		psid = pGroupInfo->Groups[index].Sid;
		LookupAccountSidA(NULL,psid, GroupName, &groupsize, DomainName, &domainsize, &sidtype);
		ConvertSidToStringSidA(psid, &sidString);
		#if _DEBUG
		printf("psid: 0x%p\nGroupName: %s\ngroupsize: %d\nDomainName: %s\ndomainsize: %d\nSID String: %s\n\n", psid, GroupName, groupsize, DomainName, domainsize, sidString);
		#endif
		if (GroupName[0]!='\0' || DomainName[0]!='\0') {
#if _DEBUG
			printf("%s\\%s -- %s\n", GroupName, DomainName,sidString);
#else
			char oneGroup[1024] = { 0 };
			sprintf_s(oneGroup,1024,"%s\\%s -- %s\n", GroupName, DomainName, sidString);
			strcat_s(allGroups, sizeof(allGroups) + sizeof(oneGroup), oneGroup);
#endif
		}
	}
#if!_DEBUG
	printf("%s\n",allGroups);
#endif

	// Token Privileges
	GetTokenInformation(tokenH, TokenPrivileges, (LPVOID)buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &ulen);
	CloseHandle(tokenH);

	PTOKEN_PRIVILEGES pPrivInfo = (PTOKEN_PRIVILEGES)buffer;
	if (pPrivInfo == NULL) {
		printf("Privileges could not be fetched.\n0x%p", GetLastError());
		return 1;
	}
	else {
		printf("The total Privileges in the Current Process are: %d\n\n", pPrivInfo->PrivilegeCount);
	}

	#if !_DEBUG
	printf("Unique Privileges:\n");
	#endif

	char allPrivileges[4096] = { 0 };

	for (int index = 0; index < pPrivInfo->PrivilegeCount; index++) {
		char* PrivName[256] = { 0 };
		char* DispName = NULL;
		char* privilege = NULL;
		DWORD priv,enabled;
		LUID luid = pPrivInfo->Privileges[index].Luid;

		#if !_DEBUG
		LookupPrivilegeNameA(NULL, &luid, &PrivName,&priv);
		if (PrivName[0]=='\0') {
			continue;
		}
		
		if (pPrivInfo->Privileges[index].Attributes& SE_PRIVILEGE_ENABLED) {
#if _DEBUG
			printf("%s Enabled\n",PrivName);
#endif
			volatile char* onePrivilege[256] = { 0 };
			sprintf_s(onePrivilege,256,"%s Enabled\n", PrivName);
			strcat_s(allPrivileges,sizeof(allPrivileges)+sizeof(onePrivilege),onePrivilege);
		}
		else {
#if _DEBUG
			printf("%s Disabled\n", PrivName);
#endif
			char* onePrivilege[256] = { 0 };
			sprintf_s(onePrivilege, 256,"%s Disabled\n", PrivName);
			strcat_s(allPrivileges, sizeof(allPrivileges) + sizeof(onePrivilege), onePrivilege);
		}
			
		#else
		printf("Privilege ID: 0x%p\n", pPrivInfo->Privileges[index].Luid);
		LookupPrivilegeNameA(NULL, &luid, &PrivName, &priv);
		printf("Privilege Name: %s ", PrivName);
		if (pPrivInfo->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED) {
			printf("Enabled\n\n");
		}
		else {
			printf("Disabled\n\n");
		}
		#endif
	}
	printf("%s", allPrivileges);
}