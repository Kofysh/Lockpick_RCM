rwildcard = $(foreach d, $(wildcard $1*), $(filter $(subst *, %, $2), $d) $(call rwildcard, $d/, $2))

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

include $(DEVKITARM)/base_rules

################################################################################

IPL_LOAD_ADDR := 0x40008000
MAGIC = 0x4B434F4C #"LOCK"
include ./Versions.inc

################################################################################

TARGET := Lockpick_RCM
BUILDDIR := build
OUTPUTDIR := output
SOURCEDIR := source
BDKDIR := bdk
BDKINC := -I./$(BDKDIR)
KEYGENDIR := keygen
KEYGEN := tsec_keygen
KEYGENH := tsec_keygen.h
VPATH = $(dir ./$(SOURCEDIR)/) $(dir $(wildcard ./$(SOURCEDIR)/*/)) $(dir $(wildcard ./$(SOURCEDIR)/*/*/))
VPATH += $(dir $(wildcard ./$(BDKDIR)/)) $(dir $(wildcard ./$(BDKDIR)/*/)) $(dir $(wildcard ./$(BDKDIR)/*/*/))

OBJS =	$(patsubst $(SOURCEDIR)/%.S, $(BUILDDIR)/$(TARGET)/%.o, \
		$(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/$(TARGET)/%.o, \
		$(call rwildcard, $(SOURCEDIR), *.S *.c)))
OBJS +=	$(patsubst $(BDKDIR)/%.S, $(BUILDDIR)/$(TARGET)/%.o, \
		$(patsubst $(BDKDIR)/%.c, $(BUILDDIR)/$(TARGET)/%.o, \
		$(call rwildcard, $(BDKDIR), *.S *.c)))

GFX_INC   := '"../$(SOURCEDIR)/gfx/gfx.h"'
FFCFG_INC := '"../$(SOURCEDIR)/libs/fatfs/ffconf.h"'

################################################################################

CUSTOMDEFINES := -DIPL_LOAD_ADDR=$(IPL_LOAD_ADDR) -DLP_MAGIC=$(MAGIC)
CUSTOMDEFINES += -DLP_VER_MJ=$(LPVERSION_MAJOR) -DLP_VER_MN=$(LPVERSION_MINOR) -DLP_VER_BF=$(LPVERSION_BUGFX) -DLP_RESERVED=$(LPVERSION_RSVD)
CUSTOMDEFINES += -DGFX_INC=$(GFX_INC) -DFFCFG_INC=$(FFCFG_INC)

#CUSTOMDEFINES += -DDEBUG

# UART Logging: Max baudrate 12.5M.
# DEBUG_UART_PORT - 0: UART_A, 1: UART_B, 2: UART_C.
#CUSTOMDEFINES += -DDEBUG_UART_BAUDRATE=115200 -DDEBUG_UART_INVERT=0 -DDEBUG_UART_PORT=0

#TODO: Considering reinstating some of these when pointer warnings have been fixed.
WARNINGS := -Wall -Wno-array-bounds -Wno-stringop-overread -Wno-stringop-overflow

ARCH := -march=armv4t -mtune=arm7tdmi -mthumb -mthumb-interwork
CFLAGS = $(ARCH) -O2 -g -nostdlib -ffunction-sections -fdata-sections -fomit-frame-pointer -fno-inline -std=gnu11 $(WARNINGS) $(CUSTOMDEFINES)
LDFLAGS = $(ARCH) -nostartfiles -lgcc -Wl,--nmagic,--gc-sections -Xlinker --defsym=IPL_LOAD_ADDR=$(IPL_LOAD_ADDR)

LDRDIR := $(wildcard loader)
TOOLSLZ := $(wildcard tools/lz)
TOOLSB2C := $(wildcard tools/bin2c)
TOOLS := $(TOOLSLZ) $(TOOLSB2C)

################################################################################

.PHONY: all clean $(LDRDIR) $(TOOLS)

all: $(OUTPUTDIR)/$(TARGET).bin $(LDRDIR)
	@echo "--------------------------------------"
	@echo -n "Uncompr size: "
	$(eval BIN_SIZE = $(shell wc -c < $(OUTPUTDIR)/$(TARGET)_unc.bin))
	@echo $(BIN_SIZE)" Bytes"
	@echo "Uncompr Max:  140288 Bytes + 3 KiB BSS"
	@if [ ${BIN_SIZE} -gt 140288 ]; then echo "\e[1;33mUncompr size exceeds limit!\e[0m"; fi
	@echo -n "Payload size: "
	$(eval BIN_SIZE = $(shell wc -c < $(OUTPUTDIR)/$(TARGET).bin))
	@echo $(BIN_SIZE)" Bytes"
	@echo "Payload Max:  126296 Bytes"
	@if [ ${BIN_SIZE} -gt 126296 ]; then echo "\e[1;33mPayload size exceeds limit!\e[0m"; fi
	@echo "--------------------------------------"

clean: $(TOOLS)
	@rm -rf $(BUILDDIR)
	@rm -rf $(OUTPUTDIR)

$(LDRDIR): $(OUTPUTDIR)/$(TARGET).bin
	@$(TOOLSLZ)/lz77 $(OUTPUTDIR)/$(TARGET).bin
	mv $(OUTPUTDIR)/$(TARGET).bin $(OUTPUTDIR)/$(TARGET)_unc.bin
	@mv $(OUTPUTDIR)/$(TARGET).bin.00.lz payload_00
	@mv $(OUTPUTDIR)/$(TARGET).bin.01.lz payload_01
	@$(TOOLSB2C)/bin2c payload_00 > $(LDRDIR)/payload_00.h
	@$(TOOLSB2C)/bin2c payload_01 > $(LDRDIR)/payload_01.h
	@rm payload_00
	@rm payload_01
	@$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS) -$(MAKEFLAGS) PAYLOAD_NAME=$(TARGET)

$(TOOLS):
	@$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS) -$(MAKEFLAGS)

$(OUTPUTDIR)/$(TARGET).bin: $(BUILDDIR)/$(TARGET)/$(TARGET).elf $(TOOLS)
	@mkdir -p "$(@D)"
	$(OBJCOPY) -S -O binary $< $@

$(BUILDDIR)/$(TARGET)/$(TARGET).elf: $(OBJS)
	@$(CC) $(LDFLAGS) -T $(SOURCEDIR)/link.ld $^ -o $@
	@echo "Lockpick_RCM was built with the following flags:\nCFLAGS:  "$(CFLAGS)"\nLDFLAGS: "$(LDFLAGS)

$(OBJS): | $(KEYGENDIR)

$(KEYGENDIR): $(TOOLS)
	@cd $(KEYGENDIR) && ../$(TOOLSB2C)/bin2c $(KEYGEN) > $(KEYGENH)

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p "$(@D)"
	@echo Building $@
	@$(CC) $(CFLAGS) $(BDKINC) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.S
	@mkdir -p "$(@D)"
	@echo Building $@
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(BDKDIR)/%.c
	@mkdir -p "$(@D)"
	@echo Building $@
	@$(CC) $(CFLAGS) $(BDKINC) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(BDKDIR)/%.S
	@mkdir -p "$(@D)"
	@echo Building $@
	@$(CC) $(CFLAGS) -c $< -o $@
