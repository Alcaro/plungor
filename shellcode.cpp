// This file contains a piece of shellcode. If injected into a process, it loads a DLL and calls a function in it.
// It doesn't contain any relocations nor imports.

#ifdef THE_SHELLCODE
#include <windows.h>
#include <stdint.h>

#ifdef __i386__
__asm__(R"(
.data
.code32

.globl shellcode32_start
shellcode32_start:
.globl _shellcode32_start
_shellcode32_start:

subd [%esp], 5 # mangle return address
push %ebx # preserve a reg for the kernel32 HMODULE

mov %eax, fs:[0x30] # eax = TEB::Peb aka PEB*
mov %eax, [%eax+0x0C] # eax = PEB::Ldr aka PEB_LDR_DATA*
mov %eax, [%eax+0x0C] # eax = PEB_LDR_DATA::InLoadOrderModuleList.Flink aka LDR_MODULE* for the exe
mov %eax, [%eax+0x00] # eax = LDR_MODULE::InLoadOrderModuleList.Flink aka LDR_MODULE* for ntdll
mov %eax, [%eax+0x00] # eax = LDR_MODULE::InLoadOrderModuleList.Flink aka LDR_MODULE* for kernel32
mov %ebx, [%eax+0x18] # ebx = LDR_MODULE::BaseAddress aka HMODULE

call 1f # I could change these calls to lea %eax, [%esi+LoadLibraryA]; push %eax, but no real point
1:
addd [%esp], LoadLibraryA-1b
push %ebx
call _pe_get_proc_address@8
call 1f
1:
addd [%esp], shellcode32_end+5-1b
call %eax

call 1f
1:
addd [%esp], PlungorInit-1b
push %eax
call _pe_get_proc_address@8
test %eax,%eax # allow injecting dlls other than Plungor
je 1f
call %eax
1:

call 1f
1:
addd [%esp], WriteProcessMemory-1b
push %ebx
call _pe_get_proc_address@8
push 0 # lpNumberOfBytesWritten
push 5 # nSize
call 1f
1:
addd [%esp], shellcode32_end-1b # lpBuffer
push [%esp+16] # lpBaseAddress
push -1 # hProcess
call %eax

# I think tail calling VirtualFree is possible on i386 stdcall abi, but if I can't do it on 64bit, no point trying here either

pop %ebx

ret

LoadLibraryA: .ascii "LoadLibraryA\0"
PlungorInit: .ascii "PlungorInit\0"
WriteProcessMemory: .ascii "WriteProcessMemory\0"

)");
#else
__asm__(R"(
.data
.code64

.globl shellcode64_start
shellcode64_start:
.globl _shellcode64_start
_shellcode64_start:

subq [%rsp], 12 # mangle return address
push %rbx # preserve a reg for the kernel32 HMODULE
sub %rsp, 40 # parameter home space (40 plus one push is misaligned, but our caller also misaligns, so this restores it)

mov %rax, gs:[0x60] # rax = TEB::Peb aka PEB*
mov %rax, [%rax+0x18] # rax = PEB::Ldr aka PEB_LDR_DATA*
mov %rax, [%rax+0x10] # rax = PEB_LDR_DATA::InLoadOrderModuleList.Flink aka LDR_MODULE* for the exe
mov %rax, [%rax+0x00] # rax = LDR_MODULE::InLoadOrderModuleList.Flink aka LDR_MODULE* for ntdll
mov %rax, [%rax+0x00] # rax = LDR_MODULE::InLoadOrderModuleList.Flink aka LDR_MODULE* for kernel32
mov %rbx, [%rax+0x30] # rbx = LDR_MODULE::BaseAddress aka HMODULE

mov %rcx, %rbx
lea %rdx, [%rip+LoadLibraryA]
call pe_get_proc_address
lea %rcx, [%rip+shellcode64_end+12] # lpLibFileName
call %rax

mov %rcx, %rax
lea %rdx, [%rip+PlungorInit]
call pe_get_proc_address
test %rax,%rax # allow injecting dlls other than Plungor
je 1f
call %rax
1:

mov %rcx, %rbx
lea %rdx, [%rip+WriteProcessMemory]
call pe_get_proc_address
mov %rcx, -1 # hProcess
mov %rdx, [%rsp+48] # lpBaseAddress aka our return address
lea %r8, [%rip+shellcode64_end] # lpBuffer
mov %r9, 12 # nSize
movq [%rsp+32], 0 # lpNumberOfBytesWritten
call %rax

# I'd prefer if I could tail call VirtualFree and delete this shellcode, but tail call to function entry is impossible in ms64 abi
# after function return, the top 32 bytes are garbage; caller may have used them as scratch space
# at function entry, the top 8 bytes are the return address
# as such, a tail call returning into a function entry is impossible

add %rsp, 40
pop %rbx
ret

LoadLibraryA: .ascii "LoadLibraryA\0"
PlungorInit: .ascii "PlungorInit\0"
WriteProcessMemory: .ascii "WriteProcessMemory\0"

)");
#endif

static inline bool streq(const char * a, const char * b) // no strcmp, it's an OS facility
{
	while (true)
	{
		if (*a != *b) return false;
		if (!*a) return true;
		a++;
		b++;
	}
}

static inline IMAGE_NT_HEADERS* pe_get_nt_headers(HMODULE mod)
{
	uint8_t* base_addr = (uint8_t*)mod;
	IMAGE_DOS_HEADER* head_dos = (IMAGE_DOS_HEADER*)base_addr;
	return (IMAGE_NT_HEADERS*)(base_addr + head_dos->e_lfanew);
}
static inline IMAGE_DATA_DIRECTORY* pe_get_section_header(HMODULE mod, int sec)
{
	return &pe_get_nt_headers(mod)->OptionalHeader.DataDirectory[sec];
}
static inline void* pe_get_section_body(HMODULE mod, int sec)
{
	return (uint8_t*)mod + pe_get_section_header(mod, sec)->VirtualAddress;
}

extern "C" void* __stdcall pe_get_proc_address(HMODULE mod, const char * name)
{
	uint8_t* base_addr = (uint8_t*)mod;
	IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)pe_get_section_body(mod, IMAGE_DIRECTORY_ENTRY_EXPORT);
	
	DWORD * addr_off = (DWORD*)(base_addr + exports->AddressOfFunctions);
	DWORD * name_off = (DWORD*)(base_addr + exports->AddressOfNames);
	WORD * ordinal = (WORD*)(base_addr + exports->AddressOfNameOrdinals);
	
	for (size_t i=0;i<exports->NumberOfNames;i++)
	{
		const char * exp_name = (const char*)(base_addr + name_off[i]);
		if (streq(name, exp_name))
			return base_addr + addr_off[ordinal[i]];
	}
	return NULL;
}

#ifdef __i386__
__asm__(R"(
.globl shellcode32_end
shellcode32_end:
.globl _shellcode32_end
_shellcode32_end:
)");
#else
__asm__(R"(
.globl shellcode64_end
shellcode64_end:
.globl _shellcode64_end
_shellcode64_end:
)");
#endif

#endif
