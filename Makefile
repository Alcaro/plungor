include arlib/Makefile-head

ifneq ($(OS),windows)
  ifneq ($(MAKECMDGOALS),clean)
    $(error Windows only)
  endif
endif

PROGRAM = plungor$(WINBITS)
ARTERMINAL = 0
CONF_CFLAGS += -masm=intel
CONF_LFLAGS += -lntdll

# Binaries from this project contain both 32- and 64-bit code.
# This is implemented by having 32bit and 64bit builds read each others' object files.
# As such, no one command can properly compile this project. Before a 64bit compile can succeed, the
#  32bit shellcode must be compiled, and vice versa. You can compile it with either 'make asm', or
#  a normal make; latter will fail, but it will successfully produce the required shellcode.
# (I could allow making a 32bit-only or 64bit-only Plungor, but former would require filling in 32bit
#  hybrid DLL support, and latter would only work on 64bit installers which are rare, so no real point.)
SOURCES += obj/shellcode32.s obj/shellcode64.s

ifeq ($(WINBITS),32)
ARTYPE = dll
asm: obj/shellcode32.s
obj/shellcode32.s: shellcode.cpp
else
ARTYPE = hybrid
asm: obj/shellcode64.s
obj/shellcode64.s: shellcode.cpp
endif
	$(ECHOQ) CC $<
	$(Q)$(CC) $< -DTHE_SHELLCODE $(OPTFLAGS) -fno-function-sections -fno-toplevel-reorder -masm=intel -Os -S -o $@

obj/%.s.o: $$(call SOURCENAME,$$@) $$(DEPS_$$(call DOMAINNAME,$$@)) | obj
	$(ECHOQ) CC $<
	$(Q)$(CC) $(TRUE_CFLAGS) $(CFLAGS_$(call DOMAINNAME,$@)) -c $< -o $@

include arlib/Makefile
