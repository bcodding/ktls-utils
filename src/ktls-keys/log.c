/**
 *  Logging helpers for ktls-agent
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

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

static int log_level;
static int log_file = 0;

int ktlsk_log_set_file(char *file_path)
{
	int ret;

	ret = open(file_path, O_CREAT|O_APPEND|O_WRONLY, 0644);
	if (ret < 0)
		return ret;

	log_file = ret;
	return 0;
}

static void ktlsk_log_file(const char *fmt, va_list args)
{
	time_t ltime;
	ltime = time(NULL);
	char *stime = ctime(&ltime);

	stime[strlen(stime) - 1] = '\0';
	dprintf(log_file, "%s: ", stime);
	vdprintf(log_file, fmt, args);
}

void ktlsk_log_debug(const char *fmt, ...)
{
	va_list args;

	if (log_level < LOG_DEBUG)
		return;

	va_start(args,fmt);
	if (log_file)
		ktlsk_log_file(fmt, args);
	else
		vsyslog(LOG_DEBUG, fmt, args);
	va_end(args);
}

void ktlsk_log(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (log_file)
		ktlsk_log_file(fmt, args);
	else
		vsyslog(LOG_INFO, fmt, args);
	va_end(args);
}

void ktlsk_log_level(int l) {
	log_level = l;
}

void ktlsk_log_init(const char *ident)
{
	log_level = LOG_INFO;
	openlog(ident, LOG_PID, LOG_DAEMON);
}

void ktlsk_log_exit()
{
	if (log_file)
		close(log_file);
	closelog();
}
