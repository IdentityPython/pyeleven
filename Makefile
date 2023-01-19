TOPDIR:=    $(abspath .)
SRCDIR=     $(TOPDIR)/src
SOURCE=     $(SRCDIR)/pyeleven

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG
