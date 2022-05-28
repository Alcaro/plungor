include arlib/Makefile-head

ifneq ($(OS),windows)
  ifneq ($(MAKECMDGOALS),clean)
    $(error Windows only)
  endif
endif

PROGRAM = plungor$(WINBITS)
ARTERMINAL = 0
ARTYPE = hybrid
CONF_CFLAGS += -masm=intel
CONF_LFLAGS += -lntdll

# Binaries from this project (by default) contain both 32- and 64-bit code.
# This is implemented by having 32bit and 64bit builds read each others' object files.
# As such, no one command can properly compile this project. Before a full 64bit compile can
#  succeed, the 32bit shellcode must be compiled, and vice versa. To do this, use 'make asm', then
#  compile the opposite-bitness version.
# Alternatively, if you only have one set of compilers, use make LOCALONLY=1. This will make Plungor
#  unable to launch programs of the other bitness.
# Plungor will compile to two EXEs, which must be placed in the same directory (doesn't matter
#  which), and may not be renamed, not even if you set LOCALONLY.
# To run a program under Plungor, drop it on either EXE (64bit recommended, the 32bit version can
#  fail to launch a few 64bit EXEs). Command line arguments can be passed after the child EXE, if
#  needed.
# Plungor is not a sandbox; a Plungor-aware program can detect it, and break out and spawn a UAC
#  prompt. (However, neither Plungor nor its children can make any UAC prompts return true without
#  user consent or a 0day.)
# Running Plungor in itself is a completely meaningless operation. It will probably work, but it's
#  not tested and will never be.

ifeq ($(LOCALONLY),1)
 DEFINES += LOCAL_ONLY
 ifeq ($(WINBITS),32)
  SOURCES += obj/shellcode32.s
 else
  SOURCES += obj/shellcode64.s
 endif
else
 SOURCES += obj/shellcode32.s obj/shellcode64.s
endif

ifeq ($(WINBITS),32)
asm: obj/shellcode32.s
obj/shellcode32.s: shellcode.cpp
else
asm: obj/shellcode64.s
obj/shellcode64.s: shellcode.cpp
endif
	$(ECHOQ) CC $<
	$(Q)$(CC) $< -DTHE_SHELLCODE $(OPTFLAGS) -fno-function-sections -fno-toplevel-reorder -masm=intel -fno-dwarf2-cfi-asm -Os -S -o $@

obj/%.s.o: $$(call SOURCENAME,$$@) $$(DEPS_$$(call DOMAINNAME,$$@)) | obj
	$(ECHOQ) CC $<
	$(Q)$(CC) $(TRUE_CFLAGS) $(CFLAGS_$(call DOMAINNAME,$@)) -c $< -o $@

include arlib/Makefile
