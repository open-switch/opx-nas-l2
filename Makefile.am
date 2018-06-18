ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc

bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_nas_l2.la

COMMON_HARDEN_FLAGS=-fexceptions -fstack-protector-strong -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wall -Wformat -Wformat-security -Werror
C_HARDEN_FLAGS=-Wimplicit-function-declaration
LD_HARDEN_FLAGS=-Wl,-z,defs -Wl,-z,now

libopx_nas_l2_la_SOURCES=src/stg/nas_stg_cps.cpp \
         src/stg/nas_stg_api.cpp src/nas_l2.cpp \
         src/sflow/nas_sflow_cps.cpp src/sflow/nas_sflow_api.cpp \
         src/mirror/nas_mirror_api.cpp src/mirror/nas_mirror_cps.cpp \
         src/mac/nas_mac_api.cpp src/mac/nas_mac_cps.cpp \
         src/mac/nas_mac_request_handler.cpp src/mac/nas_mac_events.cpp \
         src/switch/nas_switch_cps.cpp src/switch/nas_switch_mac.cpp \
         src/switch/nas_switch_log.cpp src/switch/nas_hash_cps.cpp \
         src/mcast_snooping/nas_mc_cps.cpp  src/mcast_snooping/nas_mc_main.cpp \
         src/mcast_snooping/nas_mc_proc.cpp

libopx_nas_l2_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(includedir)/opx $(COMMON_HARDEN_FLAGS) -fPIC
libopx_nas_l2_la_CXXFLAGS=-std=c++11
libopx_nas_l2_la_CFLAGS=$(C_HARDEN_FLAGS)
libopx_nas_l2_la_LDFLAGS=-shared -version-info 1:1:0 $(LD_HARDEN_FLAGS)
libopx_nas_l2_la_LIBADD=-lopx_nas_linux -lopx_common -lopx_nas_common -lopx_nas_ndi -lopx_cps_api_common -lopx_logging
