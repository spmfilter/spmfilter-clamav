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

#include <stdio.h>
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


/** check if notification_template is readable
 *
 * \param in_filename (absolute path of notification_template)
 *
 * \returns 0 if template can be read, -1 if file cannot be read
 */
static int template_exists(char *in_filename) {
	FILE *pf;
	if (pf = fopen(in_filename, "r")) {
		fclose(pf);
		return 0;
	} else {
		return -1;
	}
}

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
	
	clam_settings->notification = smf_settings_group_get_integer("notification");
	if (!clam_settings->notification)
		clam_settings->notification = 0;

	if(clam_settings->notification != 0) {
		clam_settings->notification_template = smf_settings_group_get_string("notification_template");
		if(clam_settings->notification_template == NULL) {
			TRACE(TRACE_ERR, "notification enabled but \"notification_template\" undefined");
			return -1;
		} else if (template_exists(clam_settings->notification_template) == -1) {
			TRACE(TRACE_ERR, "defined notification_template \"%s\" cannot be read",
					clam_settings->notification_template);
			return -1;
		}
		clam_settings->notification_sender = smf_settings_group_get_string("notification_sender");
		if(clam_settings->notification_sender == NULL) {
			TRACE(TRACE_ERR, "notification enabled but \"notification_sender\" undefined");
			return -1;
		}
	}
	clam_settings->notification_subject = smf_settings_group_get_string("notification_subject");
	if (clam_settings->notification_subject == NULL)
		clam_settings->notification_subject = g_strdup("Virus notification");

	clam_settings->add_header = smf_settings_group_get_boolean("add_header");
	if (!clam_settings->add_header)
		clam_settings->add_header = 0;
	
	clam_settings->header_name = smf_settings_group_get_string("header_name");
	if (clam_settings->header_name == NULL)
		clam_settings->header_name = g_strdup("X-Spmfilter-Virus-Scanned");

	clam_settings->scan_direction = smf_settings_group_get_integer("scan_direction");
	if (!clam_settings->scan_direction)
		clam_settings->scan_direction = 0;

	TRACE(TRACE_DEBUG,"clam_settings->host: %s",clam_settings->host);
	TRACE(TRACE_DEBUG,"clam_settings->port: %d",clam_settings->port);
	TRACE(TRACE_DEBUG,"clam_settings->max_scan_size: %d",clam_settings->max_scan_size);
	TRACE(TRACE_DEBUG,"clam_settings->notification: %d",clam_settings->notification);
	TRACE(TRACE_DEBUG,"clam_settings->notification_template: %s",clam_settings->notification_template);
	TRACE(TRACE_DEBUG,"clam_settings->notification_sender: %s",clam_settings->notification_sender);
	TRACE(TRACE_DEBUG,"clam_settings->notification_subject: %s",clam_settings->notification_subject);
	TRACE(TRACE_DEBUG,"clam_settings->add_header: %d",clam_settings->add_header);
	TRACE(TRACE_DEBUG,"clam_settings->header_name: %s",clam_settings->header_name);
	TRACE(TRACE_DEBUG,"clam_settings->scan_direction: %d",clam_settings->scan_direction);

	return 0;
}

char *get_template(char *template_file, char *virus, char *virus_sender) {
	FILE *fp;
	int i, count =0;
	char *template;
	int vt_newlen = strlen(virus);
	int st_newlen = strlen(virus_sender);
	int vt_oldlen = strlen(VIRUS_TOKEN);
	int st_oldlen = strlen(SENDER_TOKEN);
	int newlen;
	long len;

	if ((fp = fopen(template_file,"r")) == NULL) {
		TRACE(TRACE_ERR,"failed to open virus notify template");
		return NULL;
	}

	fseek(fp,0,SEEK_END);
	len = ftell(fp);
	fseek(fp,0,SEEK_SET); 
	template = (char *)malloc(len);
	fread(template,len,1,fp);
	fclose(fp);

	for (i = 0; template[i]; ++i) {
		if (strstr(&template[i], VIRUS_TOKEN) == &template[i])
			++count, i += vt_oldlen - 1;
		else if (strstr(&template[i], SENDER_TOKEN) == &template[i])
			++count, i += st_oldlen - 1;
  	}

	newlen = (vt_newlen - vt_oldlen) + (st_newlen - vt_oldlen);
	char *content = (char *) calloc(i + 1 + count * newlen, sizeof(char));
	if (!content) return NULL;

	i = 0;
	while (*template) {
		if (strstr(template, VIRUS_TOKEN) == template) {
			strcpy(&content[i], virus),
					i += vt_newlen,template += vt_oldlen;
		} else if (strstr(template, SENDER_TOKEN) == template) {
			strcpy(&content[i],virus_sender),
					i += st_newlen,template += st_oldlen;
		}else
			content[i++] = *template++;
  	}

	content[i] = '\0';

	return content;
}

int generate_message(char *content, char *recipient, char *nexthop) {
	SMFMessageEnvelope_T *envelope;
	SMFMessage_T *message;
	SMFMimePart_T *mime_part;
	SMFDataWrapper_T *wrapper;


	envelope = smf_message_envelope_new();
	envelope = smf_message_envelope_add_rcpt(envelope,recipient);
	envelope->from = g_strdup(clam_settings->notification_sender);
	envelope->nexthop = g_strdup(nexthop);

	message = smf_message_new();
	smf_message_set_sender(message,clam_settings->notification_sender);
	smf_message_add_recipient(message,SMF_RECIPIENT_TYPE_TO,NULL,recipient);
	smf_message_set_subject(message,clam_settings->notification_subject);

	mime_part = smf_mime_part_new(NULL,NULL);
	smf_mime_part_set_disposition(mime_part,SMF_DISPOSITION_INLINE);
	smf_mime_part_set_encoding(mime_part, SMF_CONTENT_ENCODING_DEFAULT);

	wrapper = smf_mime_data_wrapper_new(content,SMF_CONTENT_ENCODING_DEFAULT);
	smf_mime_set_content(mime_part,wrapper);

	smf_message_set_mime_part(message,mime_part);
	
	envelope->message = message;

	smf_message_deliver(envelope);
	smf_message_envelope_unref(envelope);

	return 0;
}

int send_notify(SMFSession_T *session, char *virname) {
	SMFSettings_T *settings = smf_settings_get();
	int i;
	char *mail_content = NULL;

	if (clam_settings->notification == 0) {
		return 0;
	} else {

		if (session->envelope_from != NULL)
			mail_content = get_template(clam_settings->notification_template,
							virname,session->envelope_from->addr);
		else if (session->message_from != NULL)
			mail_content = get_template(clam_settings->notification_template,
							virname,session->message_from->addr);

		if (clam_settings->notification <= 2) {
			if (session->envelope_to != NULL) {
				for (i=0; i < session->envelope_to_num; i++) {
					TRACE(TRACE_DEBUG,"sending notification to [%s]",session->envelope_to[i]->addr);
					generate_message(mail_content,
							session->envelope_to[i]->addr,
							settings->nexthop);
				}
			} else if (session->message_to != NULL) {
				for (i=0; i < session->message_to_num; i++) {
					TRACE(TRACE_DEBUG,"sending notification to [%s]",session->message_to[i]->addr);
					generate_message(mail_content,
							session->message_to[i]->addr,
							settings->nexthop);
				}
			}
		}
		if (clam_settings->notification == 2) {
			if (session->envelope_from != NULL) {
				TRACE(TRACE_DEBUG,"sending notification to [%s]",session->envelope_from->addr);
				generate_message(mail_content,
						session->envelope_from->addr,
						settings->nexthop);
			} else if (session->message_from != NULL) {
				TRACE(TRACE_DEBUG,"sending notification to [%s]",session->message_from->addr);
				generate_message(mail_content,
						session->message_from->addr,
						settings->nexthop);
			}
		}
	}

	if (mail_content != NULL)
		free(mail_content);
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


	if (session->envelope_from != NULL) {
		if ((session->envelope_from->is_local == 1) &&
				(clam_settings->scan_direction == 1)) {
			TRACE(TRACE_DEBUG,"skipping virus check; scanning only incoming connections");
			g_slice_free(ClamAVSettings_T,clam_settings);
			return 0;
		} else if ((session->envelope_from->is_local == 0) &&
				(clam_settings->scan_direction == 2)) {
			TRACE(TRACE_DEBUG,"skipping virus check; scanning only outgoing connections");
			g_slice_free(ClamAVSettings_T,clam_settings);
			return 0;
		}

	} else if (session->message_from != NULL) {
		if ((session->message_from->is_local == 1) &&
				(clam_settings->scan_direction == 1)) {
			TRACE(TRACE_DEBUG,"skipping virus check; scanning only incoming connections");
			g_slice_free(ClamAVSettings_T,clam_settings);
			return 0;
		} else if ((session->message_from->is_local == 0) &&
				(clam_settings->scan_direction == 2)) {
			TRACE(TRACE_DEBUG,"skipping virus check; scanning only outgoing connections");
			g_slice_free(ClamAVSettings_T,clam_settings);
			return 0;
		}
	}

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
		if (clam_settings->notification != 0) {
			TRACE(TRACE_INFO,"message dropped, virus [%s] detected",clam_result);
			if (send_notify(session, clam_result) != 0)
				TRACE(TRACE_WARNING,"failed to send notification mail");
		} else {
			TRACE(TRACE_INFO,"message dropped, virus [%s] detected",clam_result);
		}
	} else {
		clam_result = g_strdup("passed");
	}

	/* need to add a header? */
	if (clam_settings->add_header)
		smf_session_header_append(clam_settings->header_name,clam_result);

	if (transmit != NULL)
		free(transmit);
	g_slice_free(ClamAVSettings_T,clam_settings);


	if (strcmp(clam_result,"passed") == 0) {
		free(clam_result);
		return 0;
	} else {
		free(clam_result);
		return 1;
	}
}
