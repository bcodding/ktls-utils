/**
 *  Copyright (c) 2022 Oracle and/or its affiliates.
 *  Copyright (c) 2022 Red Hat
 *
 *  ktls-utils is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include <gnutls/gnutls.h>
#include <syslog.h>
#include <keyutils.h>
#include <asm-generic/types.h>

void ktlsk_log(const char *, ...);
void ktlsk_log_debug(const char *, ...);
void ktlsk_log_level(int);
int ktlsk_log_set_file(char *);
void ktlsk_log_init(const char *);
void ktlsk_log_exit(void);

void fatal(const char *, ...);


/* TLSH handshake types */
enum tlsh_hs_type {
	TLSH_TYPE_CLIENTHELLO_X509,
	TLSH_TYPE_CLIENTHELLO_PSK,
	TLSH_TYPE_CLIENTHELLO_ANON,
};

enum tls_keys_tls_session_op {
	TLSK_OP_CLIENTHELLO,
	TLSK_OP_CMSG,
};

/* Matching kernel struct in linux/uapi/tls.h */
struct tls_keys_tls_session_info {
	char peername[64];
	char priorities[1024];
	__u8 operation;
	__u8 operation_arg;
	char socket_token[17];
};

enum ktlsk_state_flags {
	KTLSK_STATE_NONE,
	KTLSK_STATE_HANDSHAKE,
	KTLSK_STATE_INSTANTIATED,
};

struct ktlsk_state {
	int state;
	int socket_fd;
	key_serial_t socket_fd_key;
	key_serial_t tls_session_key;
	struct tls_keys_tls_session_info *tls_info;
	gnutls_session_t tls;
	gnutls_certificate_credentials_t tls_cred;
	char tls_session_desc[1024];
};

int ktlsk_key_read_info(key_serial_t key, struct tls_keys_tls_session_info **);
void ktlsk_key_release_info(struct tls_keys_tls_session_info *);
int ktlsk_key_request_socket_fd(struct ktlsk_state *, const char *);

void ktlsk_key_debug_info(struct tls_keys_tls_session_info *);
void ktlsk_key_cleanup(struct ktlsk_state *);
void ktlsk_key_instantiate_tls(struct ktlsk_state *);

int ktlsk_client_anon_handshake(struct ktlsk_state *);

