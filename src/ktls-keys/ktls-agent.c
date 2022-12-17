/**
 *  Register as a keyaagent for tls_session keys, dispatch key
 *  requests to TLS handshakes.
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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <keyutils.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/stddef.h>

#include "ktlsk.h"

struct ka_state {
	int state;
	int sig_fd;
	key_serial_t key_serial;
	__be16 signal;
};

static char *prog;
static struct ka_state ka;

static void usage()
{
	fprintf(stderr, "usage: %s [-d] [-f logfile]\n", prog);
}

static void cleanup()
{
	if (ka.sig_fd)
		close(ka.sig_fd);
}

void fatal(const char *fmt, ...)
{
	int err = errno;
	va_list args;
	char fatal_msg[256] = "fatal: ";

	va_start(args, fmt);
	vsnprintf(&fatal_msg[7], 255, fmt, args);
	if (err) {
		ktlsk_log("%s (%m)\n", fatal_msg);
		fprintf(stderr, "%s (%m)\n", fatal_msg);
	} else {
		ktlsk_log("%s\n", fatal_msg);
		fprintf(stderr, "%s\n", fatal_msg);
	}
	cleanup();
	exit(-1);
}

int ktlsk_sig_setup()
{
	int ret;
	int sig_fd;
	sigset_t mask;

	/* Which realtime signal are we using? */
	ka.signal = SIGRTMIN + 1;

	sigemptyset(&mask);
	sigaddset(&mask, ka.signal);

	ktlsk_log_debug("Masking all but %d\n", ka.signal);

	ret = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (ret != 0)
		fatal("rt_sigprocmask");

	sig_fd = signalfd(-1, &mask, 0);
	if (sig_fd == -1)
		fatal("signalfd");

	ka.sig_fd = sig_fd;

	return ret;
}

int ktlsk_keyagent_register()
{
	key_serial_t key;

	ktlsk_log_debug("Registering as keyagent for tls_session keys with signal %d\n", ka.signal);

	/* The kernel will place authorization keys on our process keyring.
	 * Make sure we have a process keyring: */
	keyctl_get_keyring_ID(KEY_SPEC_PROCESS_KEYRING, 1);
	key = add_key("keyagent", "tls_session", &ka.signal, sizeof(unsigned int), KEY_SPEC_SESSION_KEYRING);

	if (key == -1)
		fatal("add_key");

	/* Permissions: only same user can link: */
	keyctl_setperm(key, KEY_USR_ALL);
	ka.key_serial = key;

	return 0;
}

int ktlsk_init()
{
	int ret;

	ret = ktlsk_sig_setup();
	if (ret != 0)
		return ret;

	return ktlsk_keyagent_register();
}

int ktlsk_handle_request(key_serial_t key)
{
	struct tls_keys_tls_session_info *info;
	struct ktlsk_state ktlsk;
	char *tls_session_description;
	int ret;

	memset(&ktlsk, 0, sizeof(ktlsk));

	ktlsk.tls_session_key = key;

	ktlsk_log_debug("-----------------------------------------\n");
	ktlsk_log_debug("ktlsk_handle_request with target_key %d\n", key);

	ret = ktlsk_key_read_info(key, &info);
	if (ret)
		goto out;

	ktlsk_key_debug_info(info);
	ktlsk.tls_info = info;

	ret = ktlsk_key_request_socket_fd(&ktlsk, info->socket_token);
	if (ret)
		goto out;

	switch (info->operation) {
	case TLSK_OP_CLIENTHELLO:

		/* Yuck nested switch, FIXME */
		switch (info->operation_arg) {

		case TLSH_TYPE_CLIENTHELLO_ANON:
			ret = ktlsk_client_anon_handshake(&ktlsk);
			break;
		default:
			ktlsk_log_debug("Not implemented handshake type (%d)", info->operation_arg);
			ret = -ENOKEY;
			break;
		}

		break;
	case TLSK_OP_CMSG:
		/* Not yet implented */
		ret = -ENOKEY;
		[[fallthrough]];
	default:

		ktlsk_log_debug("Not implemented operation %d", info->operation);
		break;
	}

	if (ret == 0) {
		keyctl_instantiate(key, ktlsk.tls_session_desc,
				 strlen(ktlsk.tls_session_desc), KEY_SPEC_SESSION_KEYRING);
		ktlsk.state = KTLSK_STATE_INSTANTIATED;
	} else
		ret = -ENOKEY;
out:

	ktlsk_key_cleanup(&ktlsk);

	/* you _must_ do _instantiate or _reject before this point */
	ktlsk_key_release_info(info);
	return ret;
}

int ktlsk_process()
{
	struct signalfd_siginfo fdsi;
	key_serial_t key;
	ssize_t size;
	int ret;

	for (;;) {
		size = read(ka.sig_fd, &fdsi, sizeof(struct signalfd_siginfo));

		if (size != sizeof(struct signalfd_siginfo))
			fatal("read");

		ktlsk_log_debug("received signal %d, ssi_int is %d\n", fdsi.ssi_signo, fdsi.ssi_int);
		key = fdsi.ssi_int;

		ret = ktlsk_handle_request(key);
	}
}

int main(int argc, char **argv)
{
	int opt, ret;
	char *log_file;

	prog = argv[0];

	ktlsk_log_init("ktls-agent");

	while (1) {
		int opt, prev_ind;
		int option_index = 0;
		static struct option long_options[] = {
			{"debug",	no_argument,		0, 'd' },
			{"file",	required_argument,	0, 'f' },
			{0,			0,					0, 0 }
		};

		errno = 0;
		prev_ind = optind;
		opt = getopt_long(argc, argv, ":df:", long_options, &option_index);
		if (opt == -1)
			break;

		/* Let's detect missing options in the middle of an option list */
		if (optind == prev_ind + 2 && *optarg == '-') {
			opt = ':';
			--optind;
		}

		switch (opt) {
		case 'd':
			ktlsk_log_level(LOG_DEBUG);
			break;
		case 'f':
			if (ktlsk_log_set_file(optarg))
				fatal("Cannot open log file \"%s\"", optarg);
			break;
		case ':':
			usage();
			fatal("option \"%s\" requires an argument", argv[prev_ind]);
			break;
		case '?':
			usage();
			fatal("unexpected arg \"%s\"", argv[optind - 1]);
			break;
		}
	}

	argc -= optind;

	if (argc != 0) {
		usage();
		if (argc < 0)
			fatal("Missing arguments");
		else
			fatal("Too many arguments");
	}

	if (ktlsk_init() == 0) {
		printf("Registered as keyagent with key %d\n", ka.key_serial);
		printf("Use this agent after linking with:\n\tkeyctl link %d @s\n", ka.key_serial);
		ktlsk_process();
	}
out:
	cleanup();
	exit(ret);
}
