include arlib/Makefile-head

PROGRAM = plungor
ARTERMINAL = 1
CONF_CFLAGS += -masm=intel
CONF_LFLAGS += -lntdll

# To fully recompile this project, it must be compiled thrice, at either 32 then 64 then 32 bits, or 64 then 32 then 64.
# The first one will fail, unless you limit it to building its shellcode file. The third will succeed.
SOURCES += obj/shellcode32.s obj/shellcode64.s

ifeq ($(WINBITS),32)
obj/shellcode32.s: shellcode.cpp
else
obj/shellcode64.s: shellcode.cpp
endif
	$(ECHOQ) CC $<
	$(Q)$(CC) $< -DTHE_SHELLCODE $(OPTFLAGS) -fno-toplevel-reorder -masm=intel -Os -S -o $@

obj/%.s.o: $$(call SOURCENAME,$$@) $$(DEPS_$$(call DOMAINNAME,$$@)) | obj
	$(ECHOQ) CC $<
	$(Q)$(CC) $(TRUE_CFLAGS) $(CFLAGS_$(call DOMAINNAME,$@)) -c $< -o $@

include arlib/Makefile
