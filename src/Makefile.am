AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-fno-strict-aliasing \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOGB_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-gbproxy \
	$(NULL)

osmo_gbproxy_SOURCES = \
	gb_proxy.c \
	gb_proxy_main.c \
	gb_proxy_vty.c \
	gb_proxy_ctrl.c \
	gb_proxy_peer.c \
	$(NULL)
osmo_gbproxy_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGB_LIBS) \
	-lrt \
	$(NULL)

noinst_HEADERS = \
	debug.h \
	vty.h \
	$(NULL)
