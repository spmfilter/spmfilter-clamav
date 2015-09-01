/* spmfilter-clamav - spmfilter ClamAV Plugin
 * Copyright (C) 2009-2013 Axel Steiner and SpaceNet AG
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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <spmfilter.h>
#include <spmfilter_config.h>

#include "main.h"

#define THIS_MODULE "clamav"

struct rcpt_handler_data {
  SMFSession_T *session;  
  SMFSettings_T *settings;
  ClamAVSettings_T *clam_settings;
  char *mail_content;
};

static int template_exists(char *in_filename) {
  struct stat sb;

  if (stat(in_filename,&sb) != 0) 
    return -1;

  if (access(in_filename,R_OK) != 0) 
    return -1;

  return 0;
}

void free_clam_config(ClamAVSettings_T *clam_settings) {
  if (clam_settings->host != NULL) free(clam_settings->host);
  if (clam_settings->header_name) free(clam_settings->header_name);
  if (clam_settings->notification_template) free(clam_settings->notification_template);
  if (clam_settings->notification_sender) free(clam_settings->notification_sender);
  if (clam_settings->notification_subject) free(clam_settings->notification_subject);
  if (clam_settings->reject_msg) free(clam_settings->reject_msg);
  free(clam_settings);
}

ClamAVSettings_T *get_clam_config(SMFSettings_T *settings, SMFSession_T *session) {
  ClamAVSettings_T *clam_settings = NULL;
  char *p = NULL;

  clam_settings = (ClamAVSettings_T *)calloc((size_t)1, sizeof(ClamAVSettings_T));
  clam_settings->host = NULL;
  clam_settings->notification_template = NULL;
  clam_settings->notification_sender = NULL;
  clam_settings->notification_subject = NULL;
  clam_settings->header_name = NULL;

  p = smf_settings_group_get(settings,"clamav","host");
  if (p != NULL) 
    clam_settings->host = strdup(p);
  else
    clam_settings->host = strdup("localhost");
  

  clam_settings->port = smf_settings_group_get_integer(settings,"clamav","port");
  if (!clam_settings->port) 
    clam_settings->port = 3310;
  
  clam_settings->max_scan_size = smf_settings_group_get_integer(settings,"clamav","max_scan_size");
  if (!clam_settings->max_scan_size)
    clam_settings->max_scan_size = 5242880;

  clam_settings->notification = smf_settings_group_get_integer(settings,"clamav","notification");
  if (!clam_settings->notification)
    clam_settings->notification = 0;

  p = smf_settings_group_get(settings,"clamav","notification_template");
  if (p != NULL)
    clam_settings->notification_template = strdup(p);

  if(clam_settings->notification != 0) {
    if(clam_settings->notification_template == NULL) {
      TRACE(TRACE_ERR, "notification enabled but \"notification_template\" undefined");
      free_clam_config(clam_settings);
      return NULL;
    } else if (template_exists(clam_settings->notification_template) == -1) {
      TRACE(TRACE_ERR, "defined notification_template \"%s\" cannot be read",
          clam_settings->notification_template);
      free_clam_config(clam_settings);
      return NULL;
    }

    p = smf_settings_group_get(settings,"clamav","notification_sender");
    if(p == NULL) {
      TRACE(TRACE_ERR, "notification enabled but \"notification_sender\" undefined");
      free_clam_config(clam_settings);
      return NULL;
    } else 
      clam_settings->notification_sender = strdup(p);
  }

  p = smf_settings_group_get(settings,"clamav","notification_subject");
  if (p != NULL)
    clam_settings->notification_subject = strdup(p);
  else
    clam_settings->notification_subject = strdup("Virus notification");

  clam_settings->add_header = smf_settings_group_get_boolean(settings,"clamav","add_header");
  
  p = smf_settings_group_get(settings,"clamav","header_name");
  if (p != NULL)
    clam_settings->header_name = strdup(p);  
  else
    clam_settings->header_name = strdup("X-Spmfilter-Virus-Scanned");

  clam_settings->scan_direction = smf_settings_group_get_integer(settings,"clamav","scan_direction");
  if (!clam_settings->scan_direction)
    clam_settings->scan_direction = 0;

  clam_settings->reject_virus = smf_settings_group_get_boolean(settings,"clamav","reject_virus");

  p = smf_settings_group_get(settings,"clamav","reject_msg");
  if (p != NULL)
    clam_settings->reject_msg = strdup(p);

  STRACE(TRACE_DEBUG,session->id,"clam_settings->host: %s",clam_settings->host);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->port: %d",clam_settings->port);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->max_scan_size: %d",clam_settings->max_scan_size);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->notification: %d",clam_settings->notification);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->notification_template: %s",clam_settings->notification_template);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->notification_sender: %s",clam_settings->notification_sender);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->notification_subject: %s",clam_settings->notification_subject);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->add_header: %d",clam_settings->add_header);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->header_name: %s",clam_settings->header_name);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->scan_direction: %d",clam_settings->scan_direction);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->reject_virus: %d",clam_settings->reject_virus);
  STRACE(TRACE_DEBUG,session->id,"clam_settings->reject_msg: %s",clam_settings->reject_msg);

  return clam_settings;
}

char *get_template(SMFSession_T *session, char *template_file, char *virus, char *virus_sender) {
  FILE *fp;
  int i, errno;
  char *template = NULL;
  char *it = NULL;
  int vt_newlen = strlen(virus);
  int st_newlen = strlen(virus_sender);
  int vt_oldlen = strlen(VIRUS_TOKEN);
  int st_oldlen = strlen(SENDER_TOKEN);
  int content_len = 0;
  long len;
  char *content = NULL;

  if ((fp = fopen(template_file,"r")) == NULL) {
    STRACE(TRACE_ERR,session->id,"failed to open virus notify template");
    return NULL;
  }

  if (fseek(fp,0,SEEK_END) != 0) {
    STRACE(TRACE_ERR,session->id,"seek failed: %s",strerror(errno));
    fclose(fp);
    return NULL;
  }
  len = ftell(fp);
  if (len == -1) {
    STRACE(TRACE_ERR,session->id,"tell failed: %s",strerror(errno));
    fclose(fp);
    return NULL;
  }
  
  if (fseek(fp,0,SEEK_SET) != 0) {
    STRACE(TRACE_ERR,session->id,"seek failed: %s",strerror(errno));
    fclose(fp);
    return NULL;
  }
  template = (char *)calloc(len + 1,sizeof(char));

  if (fread(template,sizeof(char),len,fp) == 0) {
    STRACE(TRACE_ERR,session->id,"seek failed: %s",strerror(errno));
    free(template);
    fclose(fp);
    return NULL;
  }
  
  fclose(fp);
  template[len] = '\0';

  content_len = len - vt_oldlen - st_oldlen + vt_newlen + st_newlen + sizeof(char);
  content = (char *)calloc(content_len,sizeof(char));
  if (!content) {
    fclose(fp);
    free(template);
    return NULL;
  }

  
  i = 0;
  it = template;
  while(*it != '\0') {
    if (strstr(it,VIRUS_TOKEN) == it) {
      strcat(content,virus);
      i += vt_newlen,it += vt_oldlen;
    } else if (strstr(it,SENDER_TOKEN) == it) {
      strcat(content,virus_sender);
      i += st_newlen, it += st_oldlen;
    } else {
      content[i++] = *it++;
    }
  }
  content[i] = '\0';
  free(template);
  return content;
}

int generate_message(SMFSession_T *session, char *sender, char *subject,
    char *content, char *recipient, char *nexthop) {
  SMFEnvelope_T *envelope = smf_envelope_new();
  SMFMessage_T *message = smf_message_create_skeleton(sender, recipient, subject);
  SMFSmtpStatus_T *status;

  if (smf_envelope_add_rcpt(envelope,recipient)!=0) {
    smf_envelope_free(envelope);
    smf_message_free(message);
    return -1;
  }
  smf_envelope_set_sender(envelope,sender);
  smf_envelope_set_nexthop(envelope,nexthop);

  if (smf_message_set_body(message,content)!=0) {
    smf_envelope_free(envelope);
    smf_message_free(message);
    return -1;
  }

  smf_envelope_set_message(envelope,message);

  status = smf_smtp_deliver(envelope,0,NULL,session->id);
  if (status->code != 250) {
    STRACE(TRACE_ERR,session->id,"delivery to [%s] failed!",nexthop);
    STRACE(TRACE_ERR,session->id,"nexthop said: %d - %s", status->code,status->text);
    return -1;
  }

  smf_smtp_status_free(status);

  return 0;
}

static void rcpt_handler(char *addr, void *user_data) {
  struct rcpt_handler_data *data = user_data;
  STRACE(TRACE_DEBUG,data->session->id,"sending notification to [%s]",addr);
  generate_message(data->session,data->clam_settings->notification_sender,
    data->clam_settings->notification_subject,
    data->mail_content,
    addr,
    data->settings->nexthop);
}

int send_notify(SMFSettings_T *settings, ClamAVSettings_T *clam_settings,SMFSession_T *session, char *virname) {
  //int i;
  char *mail_content = NULL;
  struct rcpt_handler_data data;

  if (clam_settings->notification == 0) {
    return 0;
  } else {
    if (session->envelope->sender != NULL)
      mail_content = get_template(session,clam_settings->notification_template,
              virname,session->envelope->sender);
    
    if (clam_settings->notification <= 2) 
      data.session = session;
      data.settings = settings;
      data.clam_settings = clam_settings;
      data.mail_content = mail_content;
      smf_envelope_foreach_rcpt(session->envelope, rcpt_handler, &data);
    
    if (clam_settings->notification == 2) {
      if (session->envelope->sender != NULL) {
        STRACE(TRACE_DEBUG,session->id,"sending notification to [%s]",session->envelope->sender);
        generate_message(session,clam_settings->notification_sender,
            clam_settings->notification_subject,
            mail_content,
            session->envelope->sender,
            settings->nexthop);
      }
    }
  }
  if (mail_content != NULL)
    free(mail_content);
  return 0;
}



int load(SMFSettings_T *settings, SMFSession_T *session) {
  int fd_socket, errno, ret, fh;
  struct sockaddr_in sa;
  int bytes = 0;
  uint32_t conv;
  char r_buf[BUFSIZE];
  char *transmit = NULL;
  char *clam_result = NULL;
  char *p1 = NULL;
  char *p2 = NULL;
  int len = 0;
  ClamAVSettings_T *clam_settings;

  STRACE(TRACE_DEBUG,session->id,"clamav loaded");
  clam_settings = get_clam_config(settings,session);
  if (clam_settings == NULL) {
    STRACE(TRACE_ERR,session->id,"failed to retrieve config");
    return -1;
  }

  if (session->envelope->sender != NULL) {
    if ((smf_session_is_local(session,session->envelope->sender) == 1) &&
        (clam_settings->scan_direction == 1)) {
      STRACE(TRACE_DEBUG,session->id,"skipping virus check; scanning only incoming connections");
      free_clam_config(clam_settings);
      return 0;
    } else if ((smf_session_is_local(session,session->envelope->sender) == 0)&&
        (clam_settings->scan_direction == 2)) {
      STRACE(TRACE_DEBUG,session->id,"skipping virus check; scanning only outgoing connections");
      free_clam_config(clam_settings);
      return 0;
    }
  }

  transmit = (char *)calloc((BUFSIZE + 4) * sizeof(char),sizeof(char));

  sa.sin_family = AF_INET;
  sa.sin_port = htons(clam_settings->port);
  sa.sin_addr.s_addr = inet_addr(clam_settings->host);

  STRACE(TRACE_DEBUG, session->id, "connecting to [%s] on port [%d]",clam_settings->host,clam_settings->port);
  fd_socket = socket(AF_INET, SOCK_STREAM, 0);
  if(fd_socket < 0) {
    STRACE(TRACE_ERR,session->id,"create socket failed: %s",strerror(errno));
    free(transmit);
    free_clam_config(clam_settings);
    return -1;
  }
  
  ret = connect(fd_socket, (struct sockaddr *)&sa, sizeof(sa));
  if(ret < 0) {
    STRACE(TRACE_ERR, session->id,"unable to connect to [%s]: %s", clam_settings->host, strerror(errno));
    free(transmit);
    free_clam_config(clam_settings);
    return -1;
  }

  /* open queue file */
  fh = open(session->message_file, O_RDONLY);
  if(fh < 0) {
    STRACE(TRACE_ERR, session->id,"unable to open queue file [%s]: %s", session->message_file, strerror(errno));
    close(fd_socket);
    free(transmit);
    free_clam_config(clam_settings);
    return -1;
  }

  
  STRACE(TRACE_DEBUG,session->id,"sending command zINSTREAM");
  
  ret = send(fd_socket, "zINSTREAM", 10, 0);
  if (ret <= 0) {
    STRACE(TRACE_ERR, session->id, "sending of command failed: %s",strerror(errno));
    close(fd_socket);
    close(fh);
    free(transmit);
    free_clam_config(clam_settings);
    return -1;
  }
  
  STRACE(TRACE_DEBUG,session->id,"command ok, now sending chunks...");
  conv = htonl(BUFSIZE);
  while((bytes = read(fh, r_buf, BUFSIZE)) > 0) {
    memcpy(transmit, &conv, sizeof(conv));
    memcpy(&transmit[4], r_buf, bytes);
    
    ret = send(fd_socket, transmit, BUFSIZE + 4, 0);
    if(ret <= 0) {
      STRACE(TRACE_ERR,session->id,"failed to send a chunk: %s",strerror(errno));
      close(fd_socket);
      close(fh);
      free(transmit);
      free_clam_config(clam_settings);
      return -1;
    }
    memset(transmit, 0, BUFSIZE+4); 
  }

  close(fh);

  /* this is the final chunk, to terminate instream */
  STRACE(TRACE_DEBUG,session->id,"file done, sending 0000 chunk");
  transmit[0] = 0;
  transmit[1] = 0;
  transmit[2] = 0;
  transmit[3] = 0;
  
  ret = send(fd_socket, transmit, BUFSIZE + 4, 0);
  if(ret <= 0) {
    STRACE(TRACE_DEBUG,session->id,"failed to send terminating chunk: %s",strerror(errno));
    close(fd_socket);
    free(transmit);
    free_clam_config(clam_settings);
    return -1;
  }

  /* get answer from server, will block until received */
  ret = recv(fd_socket, r_buf, BUFSIZE, 0);
  STRACE(TRACE_DEBUG,session->id,"got %d bytes back, message was: [%s]", ret, r_buf);
  close(fd_socket);

  p1 = strstr(r_buf,":");
  p1 += 2 * sizeof(char);
  clam_result = strdup(p1);

  if (strcasecmp(clam_result,"OK")!=0) {
    p1 = strstr(clam_result," FOUND");
    len = strlen(clam_result) - strlen(p1);
    p2 = (char *)calloc(len + 1,sizeof(char));
    strncpy(p2,clam_result,len);
    p2[len] = '\0';
    STRACE(TRACE_WARNING,session->id,"Virus found: [%s]", p2);

    if (clam_settings->reject_virus) {
      if (clam_settings->reject_msg != NULL)
        smf_session_set_response_msg(session,clam_settings->reject_msg);
      else
        smf_session_set_response_msg(session,"virus found, message rejected");

      free(transmit);
      free(clam_result);
      free_clam_config(clam_settings);
      free(p2);
      return 554;
    } else {
      /* do we have to send a notification? */
      if (clam_settings->notification != 0) {
        STRACE(TRACE_INFO,session->id,"message dropped, virus [%s] detected",p2);
        if (send_notify(settings,clam_settings,session, p2) != 0)
          STRACE(TRACE_WARNING,session->id,"failed to send notification mail");
      } else {
        STRACE(TRACE_INFO,session->id,"message dropped, virus [%s] detected",p2);
      }
    }

    free(p2);
  }

  /* need to add a header? */
  if (clam_settings->add_header)
    smf_message_add_header(session->envelope->message,clam_settings->header_name,clam_result);
  
  free(transmit);
  free_clam_config(clam_settings);

  if (strcasecmp(clam_result,"OK")==0) {
    free(clam_result);
    return 0;
  } else {
    smf_session_set_response_msg(session,"OK virus found, message dropped");
    free(clam_result);
    return 1;
  }
}
