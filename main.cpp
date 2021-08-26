#include "arlib.h"
#include <winternl.h>

// dll will
// - inspect the process' import table
// - overwrite CreateProcess, ShellExecute, and similar with its own versions that insert the same injector, and discard every "runas"

// Makes the program inject a DLL into itself, rather than spawn a child process. This allows debuggers to connect to it.
#define INJECT_SELF 0

#ifdef __i386__
#define PVOID64 uint64_t // mingw doesn't support 64bit pointers
#endif
static_assert(sizeof(PVOID64) == 8);

#ifdef __i386__
typedef struct _PROCESS_BASIC_INFORMATION_WOW64
{
    NTSTATUS ExitStatus;
    ULONG64  PebBaseAddress;
    ULONG64  AffinityMask;
    KPRIORITY BasePriority;
    ULONG64  UniqueProcessId;
    ULONG64  InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION_WOW64, *PPROCESS_BASIC_INFORMATION_WOW64;

typedef struct _PEB64 {
    BYTE Reserved[16];
    PVOID64 ImageBaseAddress;
    PVOID64 LdrData;
    PVOID64 ProcessParameters;
} PEB64, *PPEB64;

NTSTATUS NTAPI NtWow64ReadVirtualMemory64(
    IN HANDLE ProcessHandle,
    IN PVOID64 BaseAddress,
    OUT PVOID Buffer,
    IN ULONG64 Size,
    OUT PULONG64 NumberOfBytesRead
);

NTSTATUS NTAPI NtWow64WriteVirtualMemory64(
    IN HANDLE ProcessHandle,
    IN PVOID64 BaseAddress,
    IN PVOID Buffer,
    IN ULONG64 Size,
    OUT PULONG64 NumberOfBytesWritten
);

NTSTATUS NTAPI NtWow64QueryInformationProcess64(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

decltype(NtWow64ReadVirtualMemory64)* pNtWow64ReadVirtualMemory64 = NULL;
//decltype(NtWow64WriteVirtualMemory64)* pNtWow64WriteVirtualMemory64 = NULL;
decltype(NtWow64QueryInformationProcess64)* pNtWow64QueryInformationProcess64 = NULL;
#endif

#if INJECT_SELF
static void hello()
{
	DWORD x;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "Hello", 5, &x, NULL);
}
#endif

static bool is_process_64(HANDLE proc)
{
	if (sizeof(void*) == 4)
	{
		BOOL self;
		IsWow64Process(GetCurrentProcess(), &self);
		if (!self) return false; // if current process is 32bit and not wow, the OS is 32bit and so is every program
	}
	BOOL is32;
	IsWow64Process(proc, &is32);
	return !is32;
}


static void* get_remote_exe32_entry(HANDLE proc)
{
#if INJECT_SELF
	return (void*)hello;
#endif
	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	
	PEB peb;
	ReadProcessMemory(proc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	void* mod = peb.Reserved3[1];
	
	uint8_t header[4096];
	ReadProcessMemory(proc, mod, header, sizeof(header), NULL);
	
	IMAGE_DOS_HEADER* head_dos = (IMAGE_DOS_HEADER*)header;
	IMAGE_NT_HEADERS32* head_nt = (IMAGE_NT_HEADERS32*)(header + head_dos->e_lfanew);
	
	return (void*)((uintptr_t)mod + head_nt->OptionalHeader.AddressOfEntryPoint);
}

extern const uint8_t shellcode32_start[];
extern const uint8_t shellcode32_end[];

static void inject_dll32(HANDLE proc, const char * dll)
{
	void* entry = get_remote_exe32_entry(proc);
	
	uint8_t body_new[4096];
	memcpy(body_new, shellcode32_start, shellcode32_end-shellcode32_start);
	strcpy((char*)body_new+(shellcode32_end-shellcode32_start)+5, dll);
	
	void* body = VirtualAllocEx(proc, NULL, sizeof(body_new), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READ);
	
	uint8_t entry_new[5];
	writeu_be8(entry_new+0, 0xE8); // call rel32
	writeu_le32(entry_new+1, (uint8_t*)body-(uint8_t*)entry-5);
	
	ReadProcessMemory(proc, (void*)entry, body_new+(shellcode32_end-shellcode32_start), sizeof(entry_new), NULL);
	WriteProcessMemory(proc, (void*)entry, entry_new, sizeof(entry_new), NULL);
	WriteProcessMemory(proc, body, body_new, sizeof(body_new), NULL);
}

#ifdef __i386__
static PVOID64 get_remote_exe64_entry(HANDLE proc)
{
	PROCESS_BASIC_INFORMATION_WOW64 pbi;
	pNtWow64QueryInformationProcess64(proc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	
	PEB64 peb;
	pNtWow64ReadVirtualMemory64(proc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	PVOID64 mod = peb.ImageBaseAddress;
	
	uint8_t header[4096];
	pNtWow64ReadVirtualMemory64(proc, mod, header, sizeof(header), NULL);
	
	IMAGE_DOS_HEADER* head_dos = (IMAGE_DOS_HEADER*)header;
	IMAGE_NT_HEADERS64* head_nt = (IMAGE_NT_HEADERS64*)(header + head_dos->e_lfanew);
	
	return (PVOID64)((uint64_t)mod + head_nt->OptionalHeader.AddressOfEntryPoint);
}
#else
#define get_remote_exe64_entry get_remote_exe32_entry
#endif

extern const uint8_t shellcode64_start[];
extern const uint8_t shellcode64_end[];

static void inject_dll64(HANDLE proc, const char * dll)
{
	PVOID64 entry = get_remote_exe64_entry(proc);
	
#ifdef __i386__
	if (entry > 0xFFFFFFF0)
	{
		MessageBox(NULL, "Error", "plungor: A 32bit process tried to create a 64bit process with "
		                          "entry point above the 4GB border. This is unimplemented.", MB_OK);
		// NtWow64{Read,Write}VirtualMemory64 exist, but unlike {Read,Write}ProcessMemory, they obey page protection
		// and there's no NtWow64VirtualAlloc or Protect, so I can't flip it
		// only solution I can see is jump to 64bit code in the local process, then shellcode and find the 64bit WriteProcessMemory
		return;
	}
#endif
	
	uint8_t body_new[4096];
	memcpy(body_new, shellcode64_start, shellcode64_end-shellcode64_start);
	strcpy((char*)body_new+(shellcode64_end-shellcode64_start)+12, dll);
	
	void* body = VirtualAllocEx(proc, NULL, sizeof(body_new), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READ);
	
	uint8_t entry_new[12];
	writeu_be16(entry_new+0, 0x48B8); // mov %rax, imm64
	writeu_le64(entry_new+2, (uint64_t)body);
	writeu_be16(entry_new+10, 0xFFD0); // call %rax
	
	ReadProcessMemory(proc, (void*)entry, body_new+(shellcode64_end-shellcode64_start), sizeof(entry_new), NULL);
	WriteProcessMemory(proc, (void*)entry, entry_new, sizeof(entry_new), NULL);
	WriteProcessMemory(proc, body, body_new, sizeof(body_new), NULL);
}

static void inject_dll(HANDLE proc, const char * dll32, const char * dll64)
{
	if (is_process_64(proc)) inject_dll64(proc, dll64);
	else inject_dll32(proc, dll32);
}


int main(int argc, char** argv)
{
#ifdef __i386__
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	pNtWow64ReadVirtualMemory64 = (anyptr)GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
	//pNtWow64WriteVirtualMemory64 = (anyptr)GetProcAddress(ntdll, "NtWow64WriteVirtualMemory64");
	pNtWow64QueryInformationProcess64 = (anyptr)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
#endif
	
#if INJECT_SELF
	inject_dll(pi.hProcess, "C:\\Users\\c\\Desktop\\y\\hello32.dll", "C:\\Users\\c\\Desktop\\y\\hello64.dll");
	hello();
	return 0;
#endif
	
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	
	CreateProcess("C:\\Users\\c\\Desktop\\y\\hello32.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	printf("32=%d\n",is_process_64(pi.hProcess)); fflush(stdout);
	inject_dll(pi.hProcess, "C:\\Users\\c\\Desktop\\y\\hello32.dll", "C:\\Users\\c\\Desktop\\y\\hello64.dll");
	ResumeThread(pi.hThread);
printf("wait=%lu\n", WaitForSingleObject(pi.hProcess, 1000));
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	CreateProcess("C:\\Users\\c\\Desktop\\y\\hello64.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	printf("32=%d\n",is_process_64(pi.hProcess)); fflush(stdout);
	inject_dll(pi.hProcess, "C:\\Users\\c\\Desktop\\y\\hello32.dll", "C:\\Users\\c\\Desktop\\y\\hello64.dll");
	ResumeThread(pi.hThread);
printf("wait=%lu\n", WaitForSingleObject(pi.hProcess, 1000));
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	return 0;
}
