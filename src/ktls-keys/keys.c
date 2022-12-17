/**
 *  Interface with the linux kernel key facilities.
 *
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <keyutils.h>
#include <errno.h>

#include "ktlsk.h"

/**
 * ktlsk_key_cleanup - cleanup objects obtained via calls to the
 * keys API.
 */
void ktlsk_key_cleanup(struct ktlsk_state *ktlsk)
{
	/* if forking and process keyring, unnecessary, but no harm */
	if (ktlsk->socket_fd_key) {
		close(ktlsk->socket_fd);
		keyctl_unlink(ktlsk->socket_fd_key, KEY_SPEC_PROCESS_KEYRING);
	}

	/* If we haven't instantiated our TLS session key, reject it */
	if (ktlsk->state < KTLSK_STATE_INSTANTIATED) {
		ktlsk_log_debug("rejecting tls_session_key\n");
		keyctl_reject(ktlsk->tls_session_key, 2, EKEYREJECTED, 0);
	}
}


/**
 * ktlsk_key_request_socket_fd - use the kernel key facilities to request
 * the installation of a socket's file descriptor on this process' file
 * table.
 * @socket_token - an token representing the fd passed in a
 * tls_session key requeset
 */
int ktlsk_key_request_socket_fd(struct ktlsk_state *ktlsk,
									const char *socket_token)
{
	key_serial_t socket_fd_key;
	int socket_fd;
	size_t key_payload_size;
	int ret = 0;

	ktlsk_log_debug("calling request_key for tls_socket_fd, token %s\n", socket_token);

	/* Requesting the tls_socket_fd key will have kernel install
	 * the socket onto an empty file descriptor in this process */
	socket_fd_key = request_key("tls_socket_fd", socket_token,
								socket_token, KEY_SPEC_PROCESS_KEYRING);

	if (socket_fd_key < 0) {
		ret = errno;
		ktlsk_log("Error requesting socket_fd_key (%m)\n", socket_fd_key);
		goto out;
	}

	/* The file descriptor is read from the payload of socket_fd_key */
	key_payload_size = keyctl_read(socket_fd_key, (char *)&socket_fd, sizeof(socket_fd));
	if (key_payload_size < 0) {
		ret = errno;
		ktlsk_log("failed to retrieve socket_fd key %d payload (%m)\n", socket_fd_key);
		goto out;
	}

	ktlsk->socket_fd = socket_fd;
	ktlsk->socket_fd_key = socket_fd_key;
out:
	ktlsk_log_debug("request_sock_fd returns fd %d\n", socket_fd);

	return ret;
}

/**
 * ktlsk_key_debug_desc - parse and log the key's description
 * @key - the target key
 */
void ktlsk_key_debug_desc(key_serial_t key)
{
	/* Shamelessly copied from libkeyutils/request_key.c: */
	char *buf_type_desc, *key_type, *key_desc;
	int ntype = -1;
	int dpos = -1;
	int n;

	if (keyctl_describe_alloc(key, &buf_type_desc) < 0) {
		ktlsk_log("key %d inaccessible (%m)\n", key);
		return;
	}

	ktlsk_log_debug("Key descriptor: \"%s\"\n", buf_type_desc);

	n = sscanf(buf_type_desc, "%*[^;]%n;%*d;%*d;%x;%n", &ntype, &n, &dpos);
	if (n != 1)
		ktlsk_log("Failed to parse key description\n");

	key_type = buf_type_desc;
	key_type[ntype] = 0;
	key_desc = buf_type_desc + dpos;

	ktlsk_log_debug("key_type is %s and key_desc is %s\n", key_type, key_desc);

	/* do we need to validate the key_type?  probably not.. */
	if (strcmp(key_type, "tls_session"))
		ktlsk_log("error: this agent for tls_session keys only\n");

	free(buf_type_desc);
}

/**
 * ktlsk_key_debug_info - output members of tls_keys_session_info to the
 * debug log
 * @info - the struct pointer to dump
 */
void ktlsk_key_debug_info(struct tls_keys_tls_session_info *info)
{
	ktlsk_log_debug("peername %s\n", info->peername);
	ktlsk_log_debug("priorities %s\n", info->priorities);
	ktlsk_log_debug("operation %d\n", info->operation);
	ktlsk_log_debug("operation arg %d\n", info->operation_arg);
	ktlsk_log_debug("socket token %s\n", info->socket_token);
}

/**
 * ktlsk_key_read_info - convert a request_key() request into a
 * tls_keys_tls_session_info struct
 * @key - target key
 * @info - pointer to struct to fill in
 *
 * After success, info contains parameters from the key request.  Info must
 * be freed by the caller.
 */
int ktlsk_key_read_info(key_serial_t key,
					struct tls_keys_tls_session_info **info)
{
	key_serial_t authkey;
	size_t key_payload_size;
	int ret;

	/* We have to read the authkey to get to the callout payload */
	authkey = keyctl_assume_authority(key);
	if (authkey < 0) {
		ktlsk_log("failed to assume authority over key %d (%m)\n", key);
		goto out;
	}

	ktlsk_log_debug("ktlsk_request_key authkey %d\n", authkey);

	key_payload_size = keyctl_read_alloc(KEY_SPEC_REQKEY_AUTH_KEY, (void **)info);
	if (key_payload_size < 0)
		ktlsk_log("failed to retrieve callout info (%m)\n");
out:
	ret = errno;
	return ret;
}

/**
 * ktlsk_key_release_info - free memory allocated in _read_info and
 * release authority over the kernel caller's keys
 */
void ktlsk_key_release_info(struct tls_keys_tls_session_info *info)
{
	if (info)
		free(info);
	/* De-assume authority over the caller's keys */
	keyctl_assume_authority(0);
}

void ktlsk_key_instantiate_tls(struct ktlsk_state *ktlsk)
{
	int ret;

	ret = keyctl_assume_authority(ktlsk->tls_session_key);
	ktlsk_log_debug("keyctl_assume_authority returns %d\n", ret);

	ret = keyctl_setperm(ktlsk->tls_session_key, KEY_USR_ALL);
	ktlsk_log_debug("keyctl_setperm returns %d\n", ret);

	ret = keyctl_instantiate(ktlsk->tls_session_key, "payload", 8, KEY_SPEC_PROCESS_KEYRING);
	ktlsk_log_debug("keyctl_instantiate for tls_key_id key returns %d\n", ret);
}
