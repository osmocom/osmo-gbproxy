EXTRA_DIST = \
    osmogbproxy-usermanual.adoc \
    osmogbproxy-usermanual-docinfo.xml \
    osmogbproxy-vty-reference.xml \
    chapters \
    regen_doc.sh \
    vty \
    $(NULL)

if BUILD_MANUALS
  ASCIIDOC = osmogbproxy-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmogbproxy-usermanual.pdf: $(srcdir)/chapters/*.adoc #$(srcdir)/chapters/*.dot

  VTY_REFERENCE = osmogbproxy-vty-reference.xml

  BUILT_REFERENCE_XML = $(builddir)/vty/gbproxy_vty_reference.xml
  $(builddir)/vty/gbproxy_vty_reference.xml: $(top_builddir)/src/osmo-gbproxy
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/osmo-gbproxy --vty-ref-xml > $@

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-gbproxy
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
