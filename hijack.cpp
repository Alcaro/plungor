#include "arlib.h"
#include <shellapi.h>

// This file contains a function that scans the process' import table, and replaces
// - CreateProcess - must inject itself into child processes
// - ShellExecute - checks if the verb is runas, and if yes, call a normal CreateProcess instead (plus the above injection)
// - CheckTokenMembership - in case it asks if it's run as admin
// - GetProcAddress - in case it tries to load one of the above dynamically

void inject_self(HANDLE proc);

namespace {
HANDLE h;
static inline void say(const char * q)
{
#ifndef ARLIB_OPT
	if (!h)
	{
		h = CreateFile(file::exepath()+"plungor.log", GENERIC_READ|FILE_APPEND_DATA,
		               FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	
	DWORD x;
	WriteFile(h, q, strlen(q), &x, NULL);
#endif
}

BOOL WINAPI myCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	say("call CreateProcessA\n");
	if (lpApplicationName) { say(lpApplicationName); say("\n"); }
	if (lpCommandLine) { say(lpCommandLine); say("\n"); }
	
	BOOL ret = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags|CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	if (ret)
	{
		inject_self(lpProcessInformation->hProcess);
		if (!(dwCreationFlags&CREATE_SUSPENDED)) ResumeThread(lpProcessInformation->hThread);
	}
	return ret;
}

HINSTANCE WINAPI myShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
{
	say("call ShellExecuteA\n");
	SHELLEXECUTEINFOA sei = { sizeof(sei), SEE_MASK_FLAG_NO_UI, hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd };
	ShellExecuteExA (&sei);
	return sei.hInstApp;
}

BOOL WINAPI myShellExecuteExA(SHELLEXECUTEINFOA* pExecInfo)
{
	say("call ShellExecuteExA\n");
	if (!strcmp(pExecInfo->lpVerb, "runas"))
	{
		// ignore most of pExecInfo for now; most of it is null, nonsense for spawning an exe, or both
		// the only observed fMask is 0x00800540, SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOZONECHECKS
		
		STARTUPINFOA si = { sizeof(si) };
		si.wShowWindow = pExecInfo->nShow;
		PROCESS_INFORMATION pi;
		
		BOOL ret = myCreateProcessA(pExecInfo->lpFile, (char*)(const char*)((cstring)"\""+pExecInfo->lpFile+"\" "+pExecInfo->lpParameters),
			NULL, NULL, FALSE, 0, NULL, pExecInfo->lpDirectory, &si, &pi);
		// don't inject the dll, myCreateProcessA already did
		if (pExecInfo->fMask & SEE_MASK_NOCLOSEPROCESS)
			pExecInfo->hProcess = pi.hProcess;
		else
			CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return ret;
	}
	return ShellExecuteExA(pExecInfo);
}

/*
int WINAPI myMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	say("call MessageBoxA\n");
	char buf[1024];
		void* addrs[20];
		int n_addrs = CaptureStackBackTrace(0, ARRAY_SIZE(addrs), addrs, NULL);
		
		for (int i=0;i<n_addrs;i++)
		{
			HMODULE mod = NULL;
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			                   (char*)addrs[i], &mod);
			if (mod)
			{
				char name[PATH_MAX];
				// 80% of stack frames will be same module as last one
				// but no point optimizing, this codepath is cold
				GetModuleFileNameA(mod, name, sizeof(name));
				char * nameend = name;
				for (char * iter = name; *iter; iter++)
				{
					if (*iter == '/' || *iter == '\\') nameend = iter+1;
				}
				
				// truncate to 32 bits, easier than figuring out which of %llx, %zx, %I64x, etc work on this windows edition
				uint32_t off = (char*)addrs[i] - (char*)mod;
				sprintf(buf, "%s+0x%x (%p)\n", nameend, off, addrs[i]);
				say(buf);
			}
			else
			{
				sprintf(buf, "%p\n", addrs[i]);
				say(buf);
			}
		}
	return MessageBoxA(hWnd, lpText, lpCaption, uType);
}
*/

void* override_import(const char * name);
FARPROC WINAPI myGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	say("GetProcAddress ");
	say(lpProcName);
	say("\n");
	void* newptr = override_import(lpProcName);
	if (newptr) return (anyptr)newptr;
	else return GetProcAddress(hModule, lpProcName);
}

BOOL WINAPI myCheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember)
{
	say("CheckTokenMembership\n");
	*IsMember = TRUE;
	return TRUE;
}


template<auto fn, const char * name, typename Tr, typename... Ta>
Tr WINAPI mkwrapper_invoke(Ta... args)
{
	say(name);
	return fn(args...);
}
template<auto fn, const char * name, typename Tr, typename... Ta>
auto mkwrapper_inner(Tr (WINAPI*)(Ta...)) -> Tr (WINAPI*)(Ta...)
{
	return mkwrapper_invoke<fn, name, Tr, Ta...>;
}
template<auto fn, const char * name>
auto mkwrapper() -> decltype(fn)
{
	return mkwrapper_inner<fn, name>(fn);
}

void* override_import(const char * name)
{
	if (!strcmp(name, "CreateProcessA")) return (void*)myCreateProcessA;
	if (!strcmp(name, "ShellExecuteA")) return (void*)myShellExecuteA;
	if (!strcmp(name, "ShellExecuteEx")) return (void*)myShellExecuteExA;
	if (!strcmp(name, "ShellExecuteExA")) return (void*)myShellExecuteExA;
	//if (!strcmp(name, "MessageBoxA")) return (void*)myMessageBoxA;
	if (!strcmp(name, "GetProcAddress")) return (void*)myGetProcAddress;
	if (!strcmp(name, "CheckTokenMembership")) return (void*)myCheckTokenMembership;
//#define MAC(x) if (!strcmp(name, STR(x))) { static const char name[] = "call " STR(x) "\n"; return (anyptr)mkwrapper<x, name>(); }
#define MAC(x)
	MAC(AddFontResourceA)
	MAC(AdjustWindowRectEx)
	MAC(AllocateAndInitializeSid)
	//MAC(AlphaBlend)
	MAC(AppendMenuA)
	MAC(Arc)
	MAC(BeginPaint)
	MAC(BitBlt)
	MAC(BringWindowToTop)
	MAC(CallNextHookEx)
	MAC(CallWindowProcA)
	MAC(CallWindowProcW)
	MAC(CharLowerA)
	MAC(CharLowerBuffA)
	MAC(CharNextA)
	MAC(CharPrevA)
	MAC(CharToOemBuffA)
	MAC(CharUpperBuffA)
	MAC(CheckMenuItem)
	MAC(Chord)
	MAC(ClientToScreen)
	MAC(CloseHandle)
	//MAC(CLSIDFromProgID)
	//MAC(CoCreateInstance)
	//MAC(CoDisconnectObject)
	//MAC(CoFreeUnusedLibraries)
	//MAC(CoInitialize)
	MAC(CompareFileTime)
	MAC(CompareStringA)
	MAC(CopyFileA)
	//MAC(CoTaskMemFree)
	//MAC(CoUninitialize)
	MAC(CreateBitmap)
	MAC(CreateBrushIndirect)
	MAC(CreateCompatibleBitmap)
	MAC(CreateCompatibleDC)
	MAC(CreateDIBitmap)
	MAC(CreateDirectoryA)
	MAC(CreateEventA)
	MAC(CreateFileA)
	MAC(CreateFontIndirectA)
	MAC(CreateIcon)
	MAC(CreateMenu)
	MAC(CreateMutexA)
	MAC(CreateNamedPipeA)
	MAC(CreatePalette)
	MAC(CreatePenIndirect)
	MAC(CreatePopupMenu)
	MAC(CreateProcessA)
	MAC(CreateRectRgn)
	MAC(CreateSolidBrush)
	MAC(CreateThread)
	MAC(CreateWindowExA)
	MAC(DefFrameProcA)
	MAC(DefMDIChildProcA)
	MAC(DeleteDC)
	MAC(DeleteFileA)
	MAC(DeleteMenu)
	MAC(DeleteObject)
	MAC(DestroyCursor)
	MAC(DestroyMenu)
	MAC(DestroyWindow)
	MAC(DeviceIoControl)
	MAC(DispatchMessageA)
	MAC(DrawFocusRect)
	MAC(DrawFrameControl)
	MAC(DrawIcon)
	MAC(DrawIconEx)
	MAC(DrawMenuBar)
	MAC(DrawTextA)
	MAC(DrawTextW)
	MAC(Ellipse)
	MAC(EnableMenuItem)
	MAC(EnableWindow)
	MAC(EndPaint)
	MAC(EnumFontsA)
	MAC(EnumThreadWindows)
	MAC(EnumWindows)
	MAC(EqualRect)
	MAC(EqualSid)
	MAC(ExcludeClipRect)
	MAC(ExitProcess)
	MAC(ExitWindowsEx)
	MAC(ExtFloodFill)
	MAC(ExtractIconA)
	MAC(FileTimeToLocalFileTime)
	MAC(FileTimeToSystemTime)
	MAC(FillRect)
	MAC(FindClose)
	MAC(FindFirstFileA)
	MAC(FindNextFileA)
	MAC(FindResourceA)
	MAC(FindWindowA)
	MAC(FlushFileBuffers)
	MAC(FormatMessageA)
	MAC(FrameRect)
	MAC(FreeLibrary)
	MAC(FreeResource)
	MAC(FreeSid)
	MAC(GetACP)
	//MAC(GetActiveObject)
	MAC(GetActiveWindow)
	MAC(GetBitmapBits)
	MAC(GetCapture)
	MAC(GetClassInfoA)
	MAC(GetClassInfoW)
	MAC(GetClientRect)
	MAC(GetClipBox)
	MAC(GetCommandLineA)
	MAC(GetComputerNameA)
	MAC(GetCurrentDirectoryA)
	MAC(GetCurrentPositionEx)
	MAC(GetCurrentProcess)
	MAC(GetCurrentProcessId)
	MAC(GetCurrentThread)
	MAC(GetCurrentThreadId)
	MAC(GetCursor)
	MAC(GetCursorPos)
	MAC(GetDC)
	MAC(GetDCEx)
	MAC(GetDesktopWindow)
	MAC(GetDeviceCaps)
	MAC(GetDIBits)
	MAC(GetDiskFreeSpaceA)
	MAC(GetDriveTypeA)
	MAC(GetEnvironmentVariableA)
	MAC(GetExitCodeProcess)
	MAC(GetFileAttributesA)
	MAC(GetFileSize)
	MAC(GetFileType)
	//MAC(GetFileVersionInfoA)
	//MAC(GetFileVersionInfoSizeA)
	MAC(GetFocus)
	MAC(GetForegroundWindow)
	MAC(GetFullPathNameA)
	MAC(GetIconInfo)
	MAC(GetKeyNameTextA)
	MAC(GetKeyState)
	MAC(GetLastActivePopup)
	MAC(GetLastError)
	MAC(GetLocaleInfoA)
	MAC(GetLocalTime)
	MAC(GetLogicalDrives)
	MAC(GetMenu)
	MAC(GetMenuItemCount)
	MAC(GetMenuState)
	MAC(GetMenuStringA)
	MAC(GetMessageA)
	MAC(GetMessagePos)
	MAC(GetModuleFileNameA)
	MAC(GetModuleHandleA)
	MAC(GetObjectA)
	//MAC(GetOpenFileNameA)
	MAC(GetOverlappedResult)
	MAC(GetPaletteEntries)
	MAC(GetParent)
	MAC(GetPixel)
	MAC(GetPrivateProfileStringA)
	MAC(GetProcAddress)
	MAC(GetProfileStringA)
	MAC(GetPropA)
	//MAC(GetSaveFileNameA)
	MAC(GetScrollPos)
	MAC(GetShortPathNameA)
	MAC(GetStdHandle)
	MAC(GetStockObject)
	MAC(GetSubMenu)
	MAC(GetSysColor)
	MAC(GetSystemDefaultLCID)
	MAC(GetSystemDirectoryA)
	MAC(GetSystemInfo)
	MAC(GetSystemMenu)
	MAC(GetSystemMetrics)
	MAC(GetSystemPaletteEntries)
	MAC(GetSystemTime)
	MAC(GetSystemTimeAsFileTime)
	MAC(GetTextExtentPoint32A)
	MAC(GetTextExtentPointA)
	MAC(GetTextMetricsA)
	MAC(GetTickCount)
	MAC(GetTokenInformation)
	MAC(GetUserDefaultLangID)
	MAC(GetUserNameA)
	MAC(GetVersion)
	MAC(GetVersionExA)
	MAC(GetWindow)
	MAC(GetWindowLongA)
	MAC(GetWindowOrgEx)
	MAC(GetWindowPlacement)
	MAC(GetWindowRect)
	MAC(GetWindowRgn)
	MAC(GetWindowsDirectoryA)
	MAC(GetWindowTextA)
	MAC(GetWindowThreadProcessId)
	MAC(GlobalAddAtomA)
	MAC(GlobalAlloc)
	MAC(GlobalDeleteAtom)
	MAC(GlobalFree)
	MAC(GlobalHandle)
	MAC(GlobalLock)
	MAC(GlobalReAlloc)
	MAC(GlobalUnlock)
	//MAC(ImageList_BeginDrag)
	//MAC(ImageList_Create)
	//MAC(ImageList_Destroy)
	//MAC(ImageList_DragEnter)
	//MAC(ImageList_DragLeave)
	//MAC(ImageList_DragMove)
	//MAC(ImageList_DragShowNolock)
	//MAC(ImageList_EndDrag)
	//MAC(ImageList_GetDragImage)
	//MAC(ImageList_ReplaceIcon)
	//MAC(ImageList_SetBkColor)
	//MAC(ImageList_SetDragCursorImage)
	MAC(InflateRect)
	//MAC(InitCommonControls)
	MAC(InitializeSecurityDescriptor)
	MAC(InsertMenuA)
	MAC(InsertMenuItemA)
	//MAC(InterlockedExchange)
	MAC(IntersectClipRect)
	MAC(IntersectRect)
	MAC(InvalidateRect)
	MAC(IsBadWritePtr)
	MAC(IsDBCSLeadByte)
	MAC(IsDialogMessage)
	//MAC(IsEqualGUID)
	MAC(IsIconic)
	MAC(IsRectEmpty)
	MAC(IsWindow)
	MAC(IsWindowEnabled)
	MAC(IsWindowVisible)
	MAC(IsZoomed)
	MAC(KillTimer)
	MAC(LineDDA)
	MAC(LineTo)
	MAC(LoadBitmapA)
	MAC(LoadCursorA)
	MAC(LoadIconA)
	MAC(LoadLibraryA)
	MAC(LoadLibraryExA)
	MAC(LoadResource)
	MAC(LoadStringA)
	//MAC(LoadTypeLib)
	MAC(LocalAlloc)
	MAC(LocalFileTimeToFileTime)
	MAC(LocalFree)
	MAC(LockResource)
	MAC(LookupPrivilegeValueA)
	MAC(lstrcmp)
	MAC(MapVirtualKeyA)
	MAC(MapWindowPoints)
	MAC(MessageBeep)
	MAC(MessageBoxA)
	MAC(MoveFileA)
	MAC(MoveFileExA)
	MAC(MoveToEx)
	MAC(MsgWaitForMultipleObjects)
	MAC(MulDiv)
	MAC(MultiByteToWideChar)
	//MAC(NtdllDefWindowProc_A)
	MAC(OemToCharA)
	MAC(OemToCharBuffA)
	MAC(OffsetRect)
	MAC(OpenMutexA)
	MAC(OpenProcess)
	MAC(OpenProcessToken)
	MAC(OpenThreadToken)
	MAC(PatBlt)
	MAC(PeekMessageA)
	MAC(Pie)
	MAC(Polyline)
	MAC(PostMessageA)
	MAC(PostQuitMessage)
	MAC(PtInRect)
	MAC(QueryPerformanceCounter)
	MAC(RaiseException)
	MAC(ReadFile)
	MAC(RealizePalette)
	MAC(Rectangle)
	MAC(RectVisible)
	MAC(RegCloseKey)
	MAC(RegCreateKeyExA)
	MAC(RegDeleteKeyA)
	MAC(RegDeleteValueA)
	MAC(RegEnumKeyExA)
	MAC(RegEnumValueA)
	MAC(RegisterClassA)
	MAC(RegisterClipboardFormatA)
	//MAC(RegisterTypeLib)
	MAC(RegOpenKeyExA)
	MAC(RegQueryInfoKeyA)
	MAC(RegQueryValueExA)
	MAC(RegSetValueExA)
	MAC(ReleaseCapture)
	MAC(ReleaseDC)
	MAC(ReleaseMutex)
	MAC(RemoveDirectoryA)
	MAC(RemoveFontResourceA)
	MAC(RemoveMenu)
	MAC(RemovePropA)
	MAC(ReplyMessage)
	MAC(RestoreDC)
	MAC(RoundRect)
	//MAC(RtlDeleteCriticalSection)
	//MAC(RtlEnterCriticalSection)
	//MAC(RtlInitializeCriticalSection)
	//MAC(RtlLeaveCriticalSection)
	MAC(RtlUnwind)
	//MAC(SafeArrayCreate)
	//MAC(SafeArrayPutElement)
	MAC(SaveDC)
	MAC(ScreenToClient)
	MAC(ScrollWindow)
	MAC(ScrollWindowEx)
	MAC(SelectObject)
	MAC(SelectPalette)
	MAC(SendMessageA)
	MAC(SendMessageTimeoutA)
	MAC(SendMessageW)
	MAC(SendNotifyMessageA)
	MAC(SetActiveWindow)
	MAC(SetBkColor)
	MAC(SetBkMode)
	MAC(SetCapture)
	MAC(SetCurrentDirectoryA)
	MAC(SetCursor)
	MAC(SetEndOfFile)
	MAC(SetErrorMode)
	MAC(SetFileAttributesA)
	MAC(SetFilePointer)
	MAC(SetFileTime)
	MAC(SetFocus)
	MAC(SetForegroundWindow)
	MAC(SetLastError)
	MAC(SetMenu)
	MAC(SetNamedPipeHandleState)
	MAC(SetPixel)
	MAC(SetPropA)
	MAC(SetRect)
	MAC(SetRectEmpty)
	MAC(SetROP2)
	MAC(SetScrollInfo)
	MAC(SetScrollPos)
	MAC(SetSecurityDescriptorDacl)
	MAC(SetStretchBltMode)
	MAC(SetTextColor)
	MAC(SetTimer)
	MAC(SetViewportOrgEx)
	MAC(SetWindowLongA)
	MAC(SetWindowLongW)
	MAC(SetWindowOrgEx)
	MAC(SetWindowPlacement)
	MAC(SetWindowPos)
	MAC(SetWindowRgn)
	MAC(SetWindowsHookExA)
	MAC(SetWindowTextA)
	//MAC(SHBrowseForFolder)
	//MAC(SHChangeNotify)
	MAC(ShellExecuteA)
	MAC(ShellExecuteEx)
	MAC(SHGetFileInfo)
	//MAC(SHGetMalloc)
	//MAC(SHGetPathFromIDList)
	MAC(ShowCursor)
	MAC(ShowOwnedPopups)
	MAC(ShowWindow)
	MAC(SizeofResource)
	MAC(Sleep)
	MAC(StretchBlt)
	MAC(StretchDIBits)
	//MAC(SysAllocStringLen)
	//MAC(SysFreeString)
	//MAC(SysStringLen)
	MAC(SystemParametersInfoA)
	MAC(TerminateProcess)
	MAC(TerminateThread)
	MAC(TextOutA)
	MAC(TlsGetValue)
	MAC(TlsSetValue)
	MAC(TrackPopupMenu)
	MAC(TransactNamedPipe)
	MAC(TranslateMDISysAccel)
	MAC(TranslateMessage)
	MAC(UnhookWindowsHookEx)
	MAC(UnrealizeObject)
	MAC(UnregisterClassA)
	MAC(UpdateWindow)
	//MAC(VariantChangeTypeEx)
	//MAC(VariantClear)
	//MAC(VariantCopyInd)
	//MAC(VerQueryValueA)
	MAC(VirtualAlloc)
	MAC(VirtualFree)
	MAC(VirtualProtect)
	MAC(VirtualQuery)
	MAC(WaitForInputIdle)
	MAC(WaitForSingleObject)
	MAC(WaitMessage)
	MAC(WideCharToMultiByte)
	MAC(WindowFromPoint)
	MAC(WinHelpA)
	//MAC(WNetCloseEnum)
	//MAC(WNetEnumResourceA)
	//MAC(WNetGetConnectionA)
	//MAC(WNetGetUniversalNameA)
	//MAC(WNetOpenEnumA)
	MAC(WriteFile)
	MAC(WritePrivateProfileStringA)
	MAC(WriteProfileStringA)
	
	//say(name);
	//say("\n");
	//@
	
	return NULL;
}

IMAGE_NT_HEADERS* pe_get_nt_headers(HMODULE mod)
{
	uint8_t* base_addr = (uint8_t*)mod;
	IMAGE_DOS_HEADER* head_dos = (IMAGE_DOS_HEADER*)base_addr;
	return (IMAGE_NT_HEADERS*)(base_addr + head_dos->e_lfanew);
}
IMAGE_DATA_DIRECTORY* pe_get_section_header(HMODULE mod, int sec)
{
	return &pe_get_nt_headers(mod)->OptionalHeader.DataDirectory[sec];
}
void* pe_get_section_body(HMODULE mod, int sec)
{
	return (uint8_t*)mod + pe_get_section_header(mod, sec)->VirtualAddress;
}

void override_imports(HMODULE mod)
{
	uint8_t* base_addr = (uint8_t*)mod;
	
	IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)pe_get_section_body(mod, IMAGE_DIRECTORY_ENTRY_IMPORT);
	while (imports->Name)
	{
		//const char * libname = (char*)(base_addr + imports->Name);
		//HMODULE mod_src = GetModuleHandle(libname);
//say(libname);
//say("\n");
		
		void* * out = (void**)(base_addr + imports->FirstThunk);
		// scan the library's exports and see what this one is named
		// if OriginalFirstThunk, the names are still available, but FirstThunk-only has to work anyways, no point not using it everywhere
		
		while (*out)
		{
			// forwarder RVAs mean the imported function may end up pointing to a completely different dll
			// for example, kernel32!HeapAlloc is actually ntdll!RtlAllocateHeap
			HMODULE mod_src;
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (char*)*out, &mod_src);
			
			uint8_t* src_base_addr = (uint8_t*)mod_src;
			IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)pe_get_section_body(mod_src, IMAGE_DIRECTORY_ENTRY_EXPORT);
			
			DWORD * addr_off = (DWORD*)(src_base_addr + exports->AddressOfFunctions);
			DWORD * name_off = (DWORD*)(src_base_addr + exports->AddressOfNames);
			WORD * ordinal = (WORD*)(src_base_addr + exports->AddressOfNameOrdinals);
			for (size_t i=0;i<exports->NumberOfFunctions;i++)
			{
				if (src_base_addr+addr_off[i] == (uint8_t*)*out)
				{
					for (size_t j=0;j<exports->NumberOfNames;j++)
					{
						if (ordinal[j] == i)
						{
							void* newptr = override_import((const char*)(src_base_addr + name_off[j]));
							if (newptr)
							{
								// can't just *out = newptr, it'll blow up if the import table is in .rdata or otherwise readonly
								WriteProcessMemory(GetCurrentProcess(), out, &newptr, sizeof(newptr), NULL);
							}
							goto done;
						}
					}
say("imported a nameless function\n");
goto done;
				}
			}
say("imported a non-exported function\n");
		done:
			
			//for (size_t i=0;i<exports->NumberOfNames;i++)
			//{
			//	const char * exp_name = (const char*)(base_addr + name_off[i]);
			//	if (streq(name, exp_name))
			//		return base_addr + addr_off[ordinal[i]];
			//}
			
			out++;
		}
		imports++;
	}
}

}

#ifdef __i386__
__asm__(".section .drectve; .ascii \" -export:PlungorInit\"; .text"); // needs some extra shenanigans to kill the stdcall @0 suffix
extern "C" __stdcall void PlungorInit() __asm__("_PlungorInit");
extern "C" __stdcall void PlungorInit()
#else
DLLEXPORT void PlungorInit();
DLLEXPORT void PlungorInit()
#endif
{
	arlib_hybrid_dll_init();
	override_imports(GetModuleHandle(NULL));
}
