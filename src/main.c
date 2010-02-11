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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

#include <spmfilter.h>

#include "main.h"

#define THIS_MODULE "clamav"

ClamAVSettings_T *clam_settings;

int parse_clam_config(void) {
	clam_settings = g_slice_new(ClamAVSettings_T);

	if (smf_settings_group_load("clamav") != 0) {
		TRACE(TRACE_ERR,"config group clamav does not exist");
		return -1;
	}

	clam_settings->host = g_strdup(smf_settings_group_get_string("host"));
	
	clam_settings->port = smf_settings_group_get_integer("port");
	if (!clam_settings->port)
		clam_settings->port = 3310;

	clam_settings->max_scan_size = smf_settings_group_get_integer("max_scan_size");
	if (!clam_settings->max_scan_size)
			clam_settings->max_scan_size = 5242880;
	
	clam_settings->notification = smf_settings_group_get_boolean("notification");
	if (!clam_settings->notification)
		clam_settings->notification = 0;

	clam_settings->notification_template = smf_settings_group_get_string("notification_template");
	clam_settings->notification_sender = smf_settings_group_get_string("notification_sender");
	clam_settings->add_header = smf_settings_group_get_boolean("add_header");
	if (!clam_settings->add_header)
		clam_settings->add_header = 0;
	
	clam_settings->header_name = smf_settings_group_get_string("header_name");
	if (clam_settings->header_name == NULL)
		clam_settings->header_name = g_strdup("X-VirusScan");
	
	TRACE(TRACE_DEBUG,"clam_settings->host: %s",clam_settings->host);
	TRACE(TRACE_DEBUG,"clam_settings->port: %d",clam_settings->port);
	TRACE(TRACE_DEBUG,"clam_settings->max_scan_size: %d",clam_settings->max_scan_size);
	TRACE(TRACE_DEBUG,"clam_settings->notification: %d",clam_settings->notification);
	TRACE(TRACE_DEBUG,"clam_settings->notification_template: %s",clam_settings->notification_template);
	TRACE(TRACE_DEBUG,"clam_settings->notification_sender: %s",clam_settings->notification_sender);
	TRACE(TRACE_DEBUG,"clam_settings->add_header: %d",clam_settings->add_header);
	TRACE(TRACE_DEBUG,"clam_settings->header_name: %s",clam_settings->header_name);
	
	return 0;
}
/*
int get_template(char *template_file, char *sender, char *recipient, char *virus, char **content) {
	int fh;
	int count;
	char buffer[512];
	int pos = 0;
	char *replace;
	char *template;
	int replace_size;
	int token_size;
	
	fh = open(template_file,O_RDONLY);
	
	template = malloc(sizeof(char));
	while((count = read(fh,buffer,512))) {
		template = realloc(template,strlen(template) + count + 1);
		strncat(template,buffer,count);
	}
	close(fh);

	*content = malloc(strlen(template) + 1);

	while(*template != '\0') {
		if(*template == '%') {
			if (strncmp(template,SENDER_TOKEN,strlen(SENDER_TOKEN)) == 0) {
				replace = sender;
				replace_size = strlen(sender);
				token_size = strlen(SENDER_TOKEN);
			}	else if (strncmp(template,RECIPIENT_TOKEN,strlen(RECIPIENT_TOKEN)) == 0) {
				replace = recipient;
				replace_size = strlen(recipient);
				token_size = strlen(RECIPIENT_TOKEN);
			} else if (strncmp(template,VIRUS_TOKEN,strlen(VIRUS_TOKEN)) == 0) {
				replace = virus;
				replace_size = strlen(virus);
				token_size = strlen(VIRUS_TOKEN);
			} else {
				replace = NULL;
			}
			
			if (replace != NULL) {
				*content = realloc(*content,strlen(*content) + replace_size);
				memcpy((*content + pos), replace, replace_size);
				pos += replace_size;
				template = template + token_size;
			}
		} 
		(*content)[pos++] = *template++;
	}
	TRACE(TRACE_DEBUG,"CONTENT: %s",*content);
	return 0;
}

int generate_message(char *content, char *recipient, char *nexthop) {
	GIOChannel *fh;
	GError *error = NULL;
	MESSAGE *msg = NULL;

	msg = g_slice_new(MESSAGE);
	msg->rcpts = malloc(sizeof(char));
	msg->rcpts[0] = g_strdup(recipient);
	msg->num_rcpts = 1;
	msg->from = g_strdup(clam_settings->notification_sender);
	msg->message_file = g_strdup(gen_queue_file());
	msg->nexthop = g_strdup(nexthop);

	fh = g_io_channel_new_file(msg->message_file,"w",NULL);
	if (g_io_channel_write_chars(fh,content,-1,NULL,&error) != G_IO_STATUS_NORMAL) 
		TRACE(TRACE_ERR,"writing virus notification failed: %s", error->message);

	g_io_channel_flush(fh,NULL);
	g_io_channel_shutdown(fh,TRUE,NULL);
	g_io_channel_unref(fh);
	
	smtp_delivery(msg);
	
	g_slice_free(MESSAGE,msg);
}

int send_notify(SETTINGS *settings, MAILCONN *mconn, char *virname) {
	GIOChannel *fh;
	char *buffer;
	
	char *addr;
	int i;
	
	for (i=0; i < mconn->num_rcpts; i++) {
		char *mail_content;
		get_template(clam_settings->notification_template,
			clam_settings->notification_sender,
			mconn->rcpts[i]->addr,
			virname,
			&mail_content);
		generate_message(mail_content,mconn->rcpts[i]->addr,settings->nexthop);
		free(mail_content);
	}

	return 0;
}
*/
int load(MailConn_T *mconn) {
	int fd_socket, errno, ret, fh;
	struct sockaddr_in sa;
	int bytes = 0;
	uint32_t conv;
	char r_buf[BUFSIZE];
	char *transmit = NULL;
	char *clam_result = NULL;

	TRACE(TRACE_DEBUG,"clamav loaded");
	if (parse_clam_config()!=0)
		return -1;

	transmit = (char *)malloc((BUFSIZE + 4) * sizeof(char));

	sa.sin_family = AF_INET;
	sa.sin_port = htons(clam_settings->port);
	sa.sin_addr.s_addr = inet_addr(clam_settings->host);

	TRACE(TRACE_DEBUG, "connecting to [%s] on port [%d]",clam_settings->host,clam_settings->port);
	fd_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(fd_socket < 0) {
		TRACE(TRACE_ERR,"create socket failed: %s",strerror(errno));
		return -1; 
	}
	
	ret = connect(fd_socket, (struct sockaddr *)&sa, sizeof(sa));
	if(ret < 0) {
		TRACE(TRACE_ERR, "unable to connect to [%s]: %s", clam_settings->host, strerror(errno));
		return -1;
	}

	/* open queue file */
	fh = open(mconn->queue_file, O_RDONLY);
	if(fh < 0) {
		TRACE(TRACE_ERR, "unable to open queue file [%s]: %s", mconn->queue_file, strerror(errno));
		close(fd_socket);
		return -1;
	}

	
	TRACE(TRACE_DEBUG,"sending command zINSTREAM");
	
	ret = send(fd_socket, "zINSTREAM", 10, 0);
	if (ret <= 0) {
		TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
		close(fd_socket);
		close(fh);
		return -1;
	}
	
	TRACE(TRACE_DEBUG,"command ok, now sending chunks...");
	conv = htonl(BUFSIZE);
	while((bytes = read(fh, r_buf, BUFSIZE)) > 0) {
		memcpy(transmit, &conv, sizeof(conv));
		memcpy(&transmit[4], r_buf, bytes);
		
		ret = send(fd_socket, transmit, BUFSIZE + 4, 0);
		if(ret <= 0) {
			TRACE(TRACE_ERR,"failed to send a chunk: %s",strerror(errno));
			close(fd_socket);
			close(fh);
			return -1;
		}
		memset(transmit, 0, BUFSIZE+4); 
	}

	close(fh);

	/* this is the final chunk, to terminate instream */
	TRACE(TRACE_DEBUG,"file done, sending 0000 chunk");
	transmit[0] = 0;
	transmit[1] = 0;
	transmit[2] = 0;
	transmit[3] = 0;
	
	ret = send(fd_socket, transmit, BUFSIZE + 4, 0);
	if(ret <= 0) {
		TRACE(TRACE_DEBUG,"failed to send terminating chunk: %s",strerror(errno));
		close(fd_socket);
		return -1;
	}

	/* get answer from server, will block until received */
	ret = recv(fd_socket, r_buf, BUFSIZE, 0);
	TRACE(TRACE_DEBUG,"got %d bytes back, message was: [%s]", ret, r_buf);
	close(fd_socket);
	clam_result = smf_core_get_substring("^stream: (.*)(?!FOUND\b)\\b\\w+$",r_buf,1);

	/* virus detected? */
//	if (!MATCH(clam_result,"")) {
		/* do we have to send a notification? */
/*		if (clam_settings->notification == 1 | clam_settings->notification == 2) {
			if (send_notify(settings, mconn, clam_result) != 0) 
				TRACE(TRACE_WARNING,"failed to send notification mail");
		}
		TRACE(TRACE_DEBUG,"Virus found: %s", clam_result);
	}
*/
	/* need to add a header? */
/*	if (clam_settings->add_header) {
		if (add_header(mconn->queue_file,clam_settings->header_name,clam_result)!=0) {
			TRACE(TRACE_ERR, "failed to add header");
		}
	}
*/
	if (clam_result != NULL)
		free(clam_result);
	if (transmit != NULL)
		free(transmit);
	g_slice_free(ClamAVSettings_T,clam_settings);

	return 0;
}
