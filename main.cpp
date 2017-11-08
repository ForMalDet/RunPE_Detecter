/*
 * This Program can only analyse 32 bit Processes for now
*/
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib,"Shlwapi.lib")

//Function defination for dynamic linkage of NtQueryInfo...........
typedef NTSTATUS(WINAPI *NTQUERYINFOPROC)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS  ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

NTQUERYINFOPROC NtQueryInfoProcess;
DWORD NumOfThreats = 0;

int ResNtFunc(HMODULE ntdll)
{
	//Getting address of NtQueryInfo............
	NtQueryInfoProcess = (NTQUERYINFOPROC)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (NtQueryInfoProcess == NULL)
		return 1;

	return 0;
}

int GetDebugPrivs()
{
	//Getting SeDebugPrivileges to get debug access to processes running
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES |TOKEN_QUERY, &token))
		return 1;

	TOKEN_PRIVILEGES TokenPrivs;
	if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &(TokenPrivs.Privileges[0].Luid))) {
		CloseHandle(token);
		return 1;
	}

	TokenPrivs.PrivilegeCount = 1;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token, FALSE, &TokenPrivs, NULL, NULL, NULL)) {
		CloseHandle(token);
		return 1;
	}
	CloseHandle(token);
	return 0;

}

void Display(LPWSTR filePath,DWORD pid)
{
	LPWSTR fileName = PathFindFileName(filePath);
	printf("\nInfected Process Found\n");
	printf("Process Name: %ls\n", fileName);
	printf("Process Id of Infected Process: %d\n", pid);
	NumOfThreats++;
}

DWORD CmpNtFileHeaders(IMAGE_NT_HEADERS ProcHeader, IMAGE_NT_HEADERS ImageHeader)
{
		if(ProcHeader.FileHeader.TimeDateStamp == ImageHeader.FileHeader.TimeDateStamp){
			if(ProcHeader.FileHeader.SizeOfOptionalHeader == ImageHeader.FileHeader.SizeOfOptionalHeader){
				if(ProcHeader.FileHeader.Characteristics == ImageHeader.FileHeader.Characteristics){
					return 0;
				}
			}
		}
	return 1;
}

DWORD CmpNtOptHeaders(IMAGE_NT_HEADERS ProcHeader, IMAGE_NT_HEADERS ImageHeader)
{
	if(ProcHeader.OptionalHeader.CheckSum == ImageHeader.OptionalHeader.CheckSum){
			if(ProcHeader.OptionalHeader.AddressOfEntryPoint == ImageHeader.OptionalHeader.AddressOfEntryPoint){
				if(ProcHeader.OptionalHeader.BaseOfCode == ImageHeader.OptionalHeader.BaseOfCode){
					if(ProcHeader.OptionalHeader.BaseOfData == ImageHeader.OptionalHeader.BaseOfData){
						if(ProcHeader.OptionalHeader.SizeOfInitializedData == ImageHeader.OptionalHeader.SizeOfInitializedData){
							if(ProcHeader.OptionalHeader.SizeOfImage == ImageHeader.OptionalHeader.SizeOfImage){
								return 0;
							}
						}
					}
				}	
		}
	}
	return 1;
}

DWORD CmpSecHeaders(PIMAGE_SECTION_HEADER ProcessHeaders, PIMAGE_SECTION_HEADER ImageHeaders, int Sections)
{
	int res;
	for(int num = 0 ; num < Sections; num++)
	{
		res = 1;
		if(memcmp(ProcessHeaders[num].Name,ImageHeaders[num].Name,8) == 0){
			if(ProcessHeaders[num].VirtualAddress == ImageHeaders[num].VirtualAddress){
				if(ProcessHeaders[num].SizeOfRawData == ImageHeaders[num].SizeOfRawData){
					if(ProcessHeaders[num].Characteristics == ImageHeaders[num].Characteristics){
						res = 0;
					}
				}
			}
		}
		if(res){
			return 1;
		}
	}
	return 0;
}


int CheckAllProcesses(DWORD *ProcId, DWORD TotalProcess)
{
    //Check all processes one by one
	for(DWORD Num = 0; Num < TotalProcess; Num++)
	{
		if(ProcId[Num] == 0) //Check if pid is 0
			continue;
		HANDLE Process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcId[Num]);
		if(Process == NULL) // Did we get the handle successfully?
			continue;

		BOOL is32;
		IsWow64Process(Process, &is32); //Check if 32 bit or 64 bit
		if (is32 == FALSE) {
			CloseHandle(Process);
			continue;
		}

		PROCESS_BASIC_INFORMATION ProcInfo;
		NTSTATUS NtStat = NtQueryInfoProcess( 
			Process,
			ProcessBasicInformation, 
			&ProcInfo, 
			sizeof(PROCESS_BASIC_INFORMATION), 
			NULL);

		if (NtStat) { //Check return value of NtQueryInfo.......
			CloseHandle(Process);
			continue;
		}

		PEB RemotePEB;
		if(!ReadProcessMemory(Process, ProcInfo.PebBaseAddress, &RemotePEB, sizeof(PEB), 0)) //Get the PEB of Remote Process
		{
			CloseHandle(Process);
			return 1;
		}

		LPVOID ProcessImageBase = RemotePEB.Reserved3[1]; // Image base xD
		IMAGE_DOS_HEADER ProcessDosHeader;
		IMAGE_NT_HEADERS ProcessNtHeader;

		//Reading the Dos Headers of the process
		if(!ReadProcessMemory(Process, ProcessImageBase, &ProcessDosHeader, sizeof(IMAGE_DOS_HEADER), 0))
		{
			CloseHandle(Process);
			return 1;
		}

		//Reading the Nt Header of the process
		if(!ReadProcessMemory(
			Process,
			LPVOID(ProcessDosHeader.e_lfanew + (DWORD)ProcessImageBase),
			&ProcessNtHeader,
			sizeof(IMAGE_NT_HEADERS),
			0))
		{
			CloseHandle(Process);
			return 1;
		}

		int NumOfSecProcess = ProcessNtHeader.FileHeader.NumberOfSections;

		//Reading the Section Headers of the Process
		PIMAGE_SECTION_HEADER ProcessSecHeaders = (PIMAGE_SECTION_HEADER)malloc(
			NumOfSecProcess * sizeof(IMAGE_SECTION_HEADER));

		for(int num = 0; num < NumOfSecProcess; num++)
		{
			ReadProcessMemory(
				Process,
				LPVOID((DWORD)ProcessImageBase + ProcessDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + num * sizeof(IMAGE_SECTION_HEADER)),
				ProcessSecHeaders + num,
				sizeof(IMAGE_SECTION_HEADER),
				0);
		}

		LPWSTR filePath = (LPWSTR)malloc(1024 * sizeof(char));
		if(!GetModuleFileNameEx(Process, NULL, filePath, 1024)) // Get the path on the disk
		{
			CloseHandle(Process);
			return 1;
		}

		// Initialise file handle using path found above
		HANDLE file = CreateFile(
			filePath,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if(file == NULL) // Check if we got the handle
		{
			CloseHandle(Process);
			return 1;
		}

		IMAGE_DOS_HEADER DiskImageDosHeader;
		IMAGE_NT_HEADERS DiskImageNtHeader;

		//Reading the Dos headers from the file on Disk
		if(!ReadFile(file,&DiskImageDosHeader,sizeof(IMAGE_DOS_HEADER),NULL,NULL))
		{
			CloseHandle(Process);
			CloseHandle(file);
			return 1;
		}

		//Setting file pointer to read Nt headers
		SetFilePointer(file, DiskImageDosHeader.e_lfanew, NULL, FILE_BEGIN);

		//Reading the Nt headers from file
		if(!ReadFile(file,&DiskImageNtHeader,sizeof(IMAGE_NT_HEADERS),NULL,NULL))
		{
			CloseHandle(Process);
			CloseHandle(file);
			return 1;
		}

		SetFilePointer(file, DiskImageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), NULL, FILE_BEGIN);

		int NumOfSecImage = DiskImageNtHeader.FileHeader.NumberOfSections;

		//Reading Section Headers from file
		PIMAGE_SECTION_HEADER DiskImageSecHeaders = (PIMAGE_SECTION_HEADER)malloc(
			NumOfSecImage * sizeof(IMAGE_SECTION_HEADER));

		for(int num = 0; num < NumOfSecImage; num++)
		{
			ReadFile(file, DiskImageSecHeaders + num, sizeof(IMAGE_SECTION_HEADER), NULL, NULL);
		}

		// Check if there are same number of Sections. Dont neeed to go further if they are not xD
		if(NumOfSecProcess != NumOfSecImage) 
		{
			Display(filePath, ProcId[Num]);
			continue;
		}

		//Compare the headers of process and disk image
		DWORD DosStatus = ProcessDosHeader.e_lfanew != DiskImageDosHeader.e_lfanew ? 1 : 0;
		DWORD NtFileStatus = CmpNtFileHeaders(ProcessNtHeader, DiskImageNtHeader);
		DWORD NtOptStatus = CmpNtOptHeaders(ProcessNtHeader, DiskImageNtHeader);
		DWORD SecStatus = CmpSecHeaders(ProcessSecHeaders, DiskImageSecHeaders,NumOfSecImage);

		if(DosStatus | NtFileStatus | NtOptStatus | SecStatus)
		{
			Display(filePath,ProcId[Num]);
		}

		CloseHandle(file);
		CloseHandle(Process);
	}
	return 0;
}

int main()
{
	//Loading ntdll.dll dynamically
	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	if(ntdll == NULL){
		printf("Unable to Load Library");
		return 1;
	}

	if(ResNtFunc(ntdll)){
		printf("Failed to resolve Functions");
		return 1;
	}

	if(GetDebugPrivs())
	{
		printf("Unable to get Debug Privileges");
		return 1;
	}

	DWORD ProcId[2048], BytesFilled;
	int EnumStat = EnumProcesses( ProcId, sizeof(ProcId), &BytesFilled); //Enumerating all the running processes
	if(EnumStat == 0){
		printf("Failed to Enumerate Processes");
		return 1;
	}

	int TotalProcess = BytesFilled / sizeof(DWORD); // Total number of processes running

	int Status = CheckAllProcesses(ProcId, TotalProcess);
	if(Status)
	{
		printf("Failed! Unable to Check all the running processes");
		return 1;
	}
	
	printf("\nFinished Scanning the Memory\n");
	printf("%d threats found\n",NumOfThreats);

	FreeLibrary(ntdll);
	return 0;
}