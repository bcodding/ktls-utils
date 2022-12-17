/**
 *  Interface with GnuTLS to perform handshakes for ktls-agent
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

#include <netinet/tcp.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/tls.h>

#include "ktlsk.h"

/* TODO: use priority strings as pass in tls_session request_key */
#define GNUTLS_PRIORITIES "NONE:+VERS-TLS1.3:+AEAD:+GROUP-ALL:+SIGN-ALL:+AES-256-GCM:+PFS"

#define GNUTLS_VERIFY_ALLOW_BROKEN (GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2|GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)

#define GNUTLS_INIT_CHECK(x)\
	 ret = x;\
	 if (ret != GNUTLS_E_SUCCESS) {\
		ktlsk_log(#x " returns error: %s (%d)\n", gnutls_strerror(-ret), -ret);\
		return ret;\
	 }

static int ktlsk_tls_init(gnutls_session_t *tls)
{
	gnutls_certificate_credentials_t tls_cred;
	const char *p_err;
	int ret;

	ktlsk_log_debug("initializing gnutls\n");

	GNUTLS_INIT_CHECK(gnutls_global_init());
	GNUTLS_INIT_CHECK(gnutls_init(tls, GNUTLS_CLIENT|GNUTLS_NO_TICKETS));
	GNUTLS_INIT_CHECK(gnutls_priority_set_direct(*tls, GNUTLS_PRIORITIES, &p_err));

	return ret;
}

static void ktlsk_tls_cleanup(struct ktlsk_state *ktlsk)
{
	gnutls_session_t tls = ktlsk->tls;
	gnutls_certificate_credentials_t tls_cred = ktlsk->tls_cred;

	if (tls_cred)
		gnutls_certificate_free_credentials(tls_cred);
	if (tls)
		gnutls_deinit(tls);

	gnutls_global_deinit();
}

int ktls_tls_session_to_kernel(gnutls_session_t tls, int socket_fd)
{
	struct tls12_crypto_info_aes_gcm_256 ktls_info;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	gnutls_datum_t cipher_key;
	unsigned char seq_number[8];
	int ret;
	int sockin, sockout;

	/* Debugging: */
	{
		gnutls_cipher_algorithm_t cipher = gnutls_cipher_get(tls);
		int version = gnutls_protocol_get_version(tls);

		ktlsk_log_debug("cipher is %d, version is %d\n", cipher, version);
	}

	/* TODO: convert fatal() error handling to ktls-agent handling */
	ret = setsockopt(socket_fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
	if (ret)
		fatal("Error %d setting TLS UTLP\n", ret);

	/* Let's set up the read-side */
	ret = gnutls_record_get_state(tls, 1, &mac_key, &iv, &cipher_key, seq_number);

	if (ret)
		fatal("Error %d getting tls read crypto info from gnutls\n", ret);

	/* Debugging: */
	if (cipher_key.size != TLS_CIPHER_AES_GCM_256_KEY_SIZE)
		fatal("cipher key size %d not TLS_CIPHER_AES_GCM_256_KEY_SIZE\n");
	if (iv.size != TLS_CIPHER_AES_GCM_256_SALT_SIZE
							+ TLS_CIPHER_AES_GCM_256_IV_SIZE)
		fatal("iv key size %d not TLS_CIPHER_AES_GCM_256_SALT_SIZE + TLS_CIPHER_AES_GCM_256_IV_SIZE\n");

	memset(&ktls_info, 0, sizeof(ktls_info));

	ktls_info.info.version = TLS_1_3_VERSION;
	ktls_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;

	memcpy(ktls_info.iv, iv.data + TLS_CIPHER_AES_GCM_256_SALT_SIZE,
				TLS_CIPHER_AES_GCM_256_IV_SIZE);
	memcpy(ktls_info.salt, iv.data, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	memcpy(ktls_info.key, cipher_key.data, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
	memcpy(ktls_info.rec_seq, seq_number, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

	ret = setsockopt(socket_fd, SOL_TLS, TLS_RX, &ktls_info, sizeof(ktls_info));
	if (ret)
		fatal("Error %d on ktls setsockopt TLS_RX\n", ret);

	/* Let's set up the write-side */
	ret = gnutls_record_get_state(tls, 0, &mac_key, &iv, &cipher_key, seq_number);

	if (ret)
		fatal("Error %d getting tls read crypto info from gnutls\n", ret);

	memset(&ktls_info, 0, sizeof(ktls_info));

	ktls_info.info.version = TLS_1_3_VERSION;
	ktls_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;

	memcpy(ktls_info.iv, iv.data + TLS_CIPHER_AES_GCM_256_SALT_SIZE,
				TLS_CIPHER_AES_GCM_256_IV_SIZE);
	memcpy(ktls_info.salt, iv.data, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	memcpy(ktls_info.key, cipher_key.data, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
	memcpy(ktls_info.rec_seq, seq_number, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

	ret = setsockopt(socket_fd, SOL_TLS, TLS_TX, &ktls_info, sizeof(ktls_info));
	if (ret)
		fatal("Error %d on ktls setsockopt TLS_TX\n", ret);

	return ret;
}

int ktlsk_tls_client_hello(gnutls_session_t tls, int socket_fd)
{
	gnutls_datum_t verify_status;
	char data[1024];
	size_t record;
	int ret, count = 0;

	gnutls_transport_set_int(tls, socket_fd);
	gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		ret = gnutls_handshake(tls);
		ktlsk_log_debug("gnutls_handshake returns %d\n", ret);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	/* Let's try to be informative about what went wrong: */
	if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
			int status;
			int cert_type;

			/* check certificate verification status */
			cert_type = gnutls_certificate_type_get(tls);
			status = gnutls_session_get_verify_cert_status(tls);
			ret = gnutls_certificate_verification_status_print(status,
				  cert_type, &verify_status, 0);

			if (ret == GNUTLS_E_SUCCESS) {
				ktlsk_log("Server verify error: %s\n", verify_status);
				gnutls_free(verify_status.data);
			} else
				ktlsk_log("Server verify error: (error unknown)\n");

		}
		ktlsk_log("Handshake failed: %s\n", gnutls_strerror(ret));
		return ret;
	}

	/* OpenSSL is sending us two New Session Tickets, let's consume them: */
//	do {
//		count++;
//		usleep(10000);
//		record = gnutls_record_recv(tls, data, 256);
//		ktlsk_log_debug("gnutls_record_recv returns %d\n", record);
//	} while (record == GNUTLS_E_AGAIN && count < 2);

	ret = ktls_tls_session_to_kernel(tls, socket_fd);

	return ret;
}

#define GNUTLS_HS_CHECK(x) \
	 ret = x;\
	 if (ret != GNUTLS_E_SUCCESS) {\
		ktlsk_log(#x " returns error: %s (%d)\n", gnutls_strerror(ret), ret);\
		goto out;\
	 }

int ktlsk_client_anon_handshake(struct ktlsk_state *ktlsk)
{
	gnutls_session_t tls;
	gnutls_certificate_credentials_t tls_cred;
	int ret;

	ret = ktlsk_tls_init(&tls);
	if (ret != GNUTLS_E_SUCCESS)
		goto out;

	GNUTLS_HS_CHECK(gnutls_server_name_set(tls, GNUTLS_NAME_DNS,
					ktlsk->tls_info->peername,
					strlen(ktlsk->tls_info->peername)));
	GNUTLS_HS_CHECK(gnutls_certificate_allocate_credentials(&tls_cred));

	/* XXX Allow broken: Ben's NFS server has garbage certs! */
	gnutls_certificate_set_verify_flags(tls_cred, GNUTLS_VERIFY_ALLOW_BROKEN);
	gnutls_certificate_set_flags(tls_cred, GNUTLS_CERTIFICATE_VERIFY_CRLS);

	ret = gnutls_certificate_set_x509_system_trust(tls_cred);
	if (ret < 0) {
		ktlsk_log("gnutls_certificate_set_x509_system_trust returns error: %s (%d)\n",
				gnutls_strerror(ret), ret);
		goto out;
	}

	ktlsk_log_debug("added %d certificates from system trust store\n", ret);

	GNUTLS_HS_CHECK(gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, tls_cred));

	ret = ktlsk_tls_client_hello(tls, ktlsk->socket_fd);

	if (ret == 0)
		strncpy(ktlsk->tls_session_desc, gnutls_session_get_desc(tls),
			sizeof(ktlsk->tls_session_desc));

	ktlsk_log_debug("Session info: %s\n", ktlsk->tls_session_desc);
out:
	ktlsk->tls = tls;
	ktlsk->tls_cred = tls_cred;

	ktlsk_tls_cleanup(ktlsk);

	return ret;
}
