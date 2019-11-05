# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019 Linux Test Project

top_srcdir		?= ../../..

include $(top_srcdir)/include/mk/testcases.mk

CFLAGS			+= -D_GNU_SOURCE

ifeq ($(WITH_SYZKALLER_REPROS),yes)

# The number of reproducers in each runtest file
SYZKALLER_RUNFILES_SIZE ?= 100

# Location where reproducers are installed
SYZKALLER_INSTALL_DIR ?= $(abspath $(DESTDIR)/$(prefix)/testcases/bin)

# If the reproducers directory is missing then we automatically clone the repo.
# We then have to call make recursively to revaluate the targets
SYZKALLER_REPROS_DIR ?= $(abs_top_srcdir)/testcases/linux-arts/syzkaller-repros/linux
$(SYZKALLER_REPROS_DIR):
	git submodule update --init $(abs_top_srcdir)/testcases/linux-arts
	$(MAKE) syzkaller_runfiles

SYZKALLER_REPROS_SRCS = $(wildcard $(SYZKALLER_REPROS_DIR)/*.c)

# Some useful compiler flags for the LTP will cause problems with the
# syzkaller repros so the repros have seperate flags
SYZKALLER_CFLAGS ?= -pthread
SYZKALLER_REPROS = $(subst $(abs_top_srcdir),$(abs_top_builddir),$(SYZKALLER_REPROS_SRCS:.c=))
$(SYZKALLER_REPROS): %: %.c
	-@if grep -q "__NR_mmap2" $^; then \
		M32="-m32"; \
	fi; \
	$(CC) $(SYZKALLER_CFLAGS) $$M32 $(SYZKALLER_LDFLAGS) $^ -o $@; \
	echo $(CC) $(SYZKALLER_CFLAGS) $$M32 $(SYZKALLER_LDFLAGS) $^ -o $@;

# Generate the names of the runtest files. This uses Shell arithmetic to
# calculate how many runtest files there will be.
define SYZKALLER_RUNFILES !=
	n=$(words $(SYZKALLER_REPROS));
	m=$(SYZKALLER_RUNFILES_SIZE);
	i=$$(( $$n / $$m + ($$n % $$m > 0) ));
	while test $$i -gt 0;
	do
		echo $(top_srcdir)/runtest/syzkaller$$i;
		i=$$(($$i - 1));
	done
endef

# Get the index part of a runtest files name
syz_n = $(subst $(top_srcdir)/runtest/syzkaller,,$(1))
syz_m = $(SYZKALLER_RUNFILES_SIZE)
# Gives the index of the first reproducer in a runtest file
syz_i = $(shell echo $$((($(call syz_n,$(1)) - 1) * $(2) + 1)))
# Gives the index of the last reproducer in a runtest file
syz_j = $(shell echo $$(( $(call syz_i,$(1),$(2)) + $(2) - 1 )))
# Gvien a runtest file name, get the reproducers it should contain
syz_wordlist = $(wordlist $(call syz_i,$(1),$(syz_m)),$(call syz_j,$(1),$(syz_m)),$(SYZKALLER_REPROS))

define syz_runfile_line
$(notdir $(exe)) syzwrap -d $(SYZKALLER_INSTALL_DIR) -n $(notdir $(exe))

endef

# Generate the runtest files based on the reproducer names and batch size.
$(SYZKALLER_RUNFILES): $(SYZKALLER_REPROS)
	@echo "Writing $@"
	$(file >$@)
	$(foreach exe,$(call syz_wordlist,$@),$(file >>$@,$(syz_runfile_line)))

.PHONY: syzkaller_runfiles
syzkaller_runfiles: $(SYZKALLER_RUNFILES) | $(SYZKALLER_REPROS_DIR)

all: $(SYZKALLER_RUNFILES) | $(SYZKALLER_REPROS_DIR)

# There are too many reproducers to pass all at once to rm, so we just pass
# one at a time
syzkaller_clean:
	$(foreach f, $(SYZKALLER_REPROS), $(RM) $(f))
CLEAN_DEPS += syzkaller_clean
CLEAN_TARGETS += $(SYZKALLER_RUNFILES)

INSTALL_MODE ?= 0775

# For some reason part of the path is missing if we just try to install these
# by adding them to INSTALL_FILES
SYZKALLER_REPROS_INSTALLED := $(subst $(SYZKALLER_REPROS_DIR),$(SYZKALLER_INSTALL_DIR),$(SYZKALLER_REPROS))
$(SYZKALLER_REPROS_INSTALLED): $(SYZKALLER_INSTALL_DIR)/%: $(SYZKALLER_REPROS_DIR)/%
	install -m $(INSTALL_MODE) -T $< $@

install: $(SYZKALLER_REPROS_INSTALLED)

endif

include $(top_srcdir)/include/mk/generic_leaf_target.mk
