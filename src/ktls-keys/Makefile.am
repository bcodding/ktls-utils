# Copyright (c) 2022 Oracle and/or its affiliates.
# Copyright (c) 2022 Red Hat
#
# ktls-utils is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#

#bin_PROGRAMS			= ktls-agent ktls-request-key
bin_PROGRAMS			= ktls-agent
ktls_agent_CFLAGS		= $(GNUTLS_CFLAGS)
ktls_agent_SOURCES		= ktls-agent.c keys.c log.c tls.c
ktls_agent_LDADD		= $(LIBGNUTLS_LIBS) $(LIBKEYUTILS_LIBS)
