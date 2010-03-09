/* spmfilter-clamav - spmfilter ClamAV Plugin
 * Copyright (C) 2009-2010 Axel Steiner and SpaceNet AG
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

int get_clam_config(void) {
	clam_settings = g_slice_new(ClamAVSettings_T);

	if (smf_settings_group_load(THIS_MODULE) != 0) {
		TRACE(TRACE_ERR,"config group clamav does not exist");
		return -1;
	}

	clam_settings->host = smf_settings_group_get_string("host");
	
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

int get_template(char *template_file, char *sender, char *recipient, char *virus, char **content) {
	int fh;
	int count;
	char buffer[512];
	int pos = 0;
	char *replace;
	char *template;
	int replace_size;
	int token_size;
	
	if ((fh = open(template_file,O_RDONLY)) == -1) {
		TRACE(TRACE_ERR,"failed to open virus notification template");
		return -1;
	}
	
	template = malloc(sizeof(char));
	while((count = read(fh,buffer,512))) {
		template = realloc(template,strlen(template) + count + 1);
		strncat(template,buffer,count);
	}
	close(fh);

	*content = malloc(strlen(template) + 1);

	while(*template != '\0') {
		if(*template == '%') {
			if (strncmp(template,VIRUS_TOKEN,strlen(VIRUS_TOKEN)) == 0) {
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
//	TRACE(TRACE_DEBUG,"CONTENT: %s",*content);
	return 0;
}

int generate_message(char *content, char *recipient, char *nexthop) {
//	GIOChannel *fh;
//	GError *error = NULL;
	SMFDeliverInfo_T *info;
	SMFMessage_T *message;
	SMFMimePart_T *mime_part;
	SMFDataWrapper_T *wrapper;

	info = g_slice_new(SMFDeliverInfo_T);
	info->num_rcpts = 1;
	info->rcpts = g_malloc(sizeof(info->rcpts[info->num_rcpts]));
	info->rcpts[0] = g_strdup(recipient);
	info->from = g_strdup(clam_settings->notification_sender);
	smf_core_gen_queue_file(&info->message_file);
	info->nexthop = g_strdup(nexthop);

	message = smf_message_new();
	smf_message_set_sender(message,clam_settings->notification_sender);
	smf_message_add_recipient(message,SMF_RECIPIENT_TYPE_TO,NULL,recipient);
	smf_message_set_subject(message,"Virus notification");

	mime_part = smf_mime_part_new(NULL,NULL);
	smf_mime_part_set_encoding(mime_part, SMF_CONTENT_ENCODING_DEFAULT);
	smf_mime_part_set_disposition(mime_part,SMF_DISPOSITION_INLINE);

	wrapper = smf_mime_data_wrapper_new(content,SMF_CONTENT_ENCODING_DEFAULT);
	smf_mime_set_content(mime_part,wrapper);

	smf_message_set_mime_part(message,mime_part);
	
	info->message = message;
/*
	fh = g_io_channel_new_file(msg->message_file,"w",NULL);
	if (g_io_channel_write_chars(fh,smf_message_to_string(message),-1,NULL,&error) != G_IO_STATUS_NORMAL)
		TRACE(TRACE_ERR,"writing virus notification failed: %s", error->message);

	g_io_channel_flush(fh,NULL);
	g_io_channel_shutdown(fh,TRUE,NULL);
	g_io_channel_unref(fh);
*/
	smf_message_deliver(info);
	
	g_slice_free(SMFDeliverInfo_T,info);

	return 0;
}

int send_notify(SMFSession_T *session, char *virname) {
//	GIOChannel *fh;
	SMFSettings_T *settings = smf_settings_get();
//	char *buffer;
	
//	char *addr;
	int i;
	
	for (i=0; i < session->envelope_to_num; i++) {
		char *mail_content = NULL;
		/* send notify to local user only */
		if ((clam_settings->notification == 1) &&
				(session->envelope_to[i]->is_local ==1)) {

		/*	get_template(clam_settings->notification_template,
				clam_settings->notification_sender,
				session->envelope_to[i]->addr,
				virname,
				&mail_content);
		*/
			generate_message(mail_content,session->envelope_to[i]->addr,settings->nexthop);

		}
		
		if (mail_content != NULL)
			free(mail_content);
	}

	return 0;
}



int load(SMFSession_T *session) {
	int fd_socket, errno, ret, fh;
	struct sockaddr_in sa;
	int bytes = 0;
	uint32_t conv;
	char r_buf[BUFSIZE];
	char *transmit = NULL;
	char *clam_result = NULL;

	TRACE(TRACE_DEBUG,"clamav loaded");
	if (get_clam_config()!=0)
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
	fh = open(session->queue_file, O_RDONLY);
	if(fh < 0) {
		TRACE(TRACE_ERR, "unable to open queue file [%s]: %s", session->queue_file, strerror(errno));
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
	if (strcmp(clam_result,"") != 0) {
		TRACE(TRACE_DEBUG,"Virus found: %s", clam_result);
		/* do we have to send a notification? */
		if ((clam_settings->notification == 1) || (clam_settings->notification == 2)) {
			if (send_notify(session, clam_result) != 0)
				TRACE(TRACE_WARNING,"failed to send notification mail");
		} 
	} else {
		clam_result = g_strdup("Ok");
	}

	/* need to add a header? */
	if (clam_settings->add_header)
		smf_session_header_append(clam_settings->header_name,clam_result);

	if (clam_result != NULL)
		free(clam_result);
	if (transmit != NULL)
		free(transmit);
	g_slice_free(ClamAVSettings_T,clam_settings);

	return 0;
}
