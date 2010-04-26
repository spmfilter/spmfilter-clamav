/* spmfilter-clamav - spmfilter ClamAV Plugin
 * Copyright (C) 2009-2010 Werner Detter and SpaceNet AG
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MAIN_H
#define	_MAIN_H

#define VIRUS_TOKEN "%virus%"
#define SENDER_TOKEN "%sender%"


enum {
	BUFSIZE = 1024
};

typedef struct {
	gchar *host;
	int port;
	int max_scan_size;
	int add_header;
	gchar *header_name;
	int notification;
	gchar *notification_template;
	gchar *notification_sender;
	gchar *notification_subject;
	int scan_direction;
	int reject_virus;
	gchar *reject_msg;
} ClamAVSettings_T;

#endif	/* _MAIN_H */

