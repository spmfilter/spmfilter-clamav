/*
 * spmfilter clamav plugin
 */

#define _GNU_SOURCE

#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <spmfilter.h>

#define THIS_MODULE "clamav"

enum {
	BUFSIZE = 512
};

typedef struct {
	char *host;
	int port;
	int max_scan_size;
	gboolean add_header;
	gboolean send_report;
	char *header_name;
} CLAMAV_SETTINGS;

int parse_clam_config(SETTINGS *settings, CLAMAV_SETTINGS *clam_settings) {
	GError *error = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile, settings->config_file, G_KEY_FILE_NONE, &error)) {
		TRACE(TRACE_ERR,"rrror loading config: %sn",error->message);
		return -1;
	}

	clam_settings->host = g_key_file_get_string(keyfile,"clamav","host",NULL);
	if (clam_settings->host == NULL) 
		clam_settings->host = g_strdup("127.0.0.1");

	clam_settings->port = g_key_file_get_integer(keyfile,"clamav","port",NULL);
	if (!clam_settings->port)
		clam_settings->port = 3310;
	
	clam_settings->max_scan_size = g_key_file_get_integer(keyfile,"clamav","max_scan_size",NULL);
	if (!clam_settings->max_scan_size)
		clam_settings->max_scan_size = 5242880;
	
	clam_settings->send_report = g_key_file_get_boolean(keyfile,"clamav","send_report",NULL);
	if (!clam_settings->send_report)
		clam_settings->send_report = FALSE;
	
	clam_settings->add_header = g_key_file_get_boolean(keyfile,"clamav","add_header",NULL);
	if (!clam_settings->add_header)
		clam_settings->add_header = FALSE;
	
	clam_settings->header_name = g_key_file_get_string(keyfile,"clamav","header_name",NULL);
	if (clam_settings->header_name == NULL)
		clam_settings->header_name = g_strdup("X-VirusScan");
	
	TRACE(TRACE_DEBUG,"clam_settings->host: %s",clam_settings->host);
	TRACE(TRACE_DEBUG,"clam_settings->port: %d",clam_settings->port);
	TRACE(TRACE_DEBUG,"clam_settings->max_scan_size: %d",clam_settings->max_scan_size);
	TRACE(TRACE_DEBUG,"clam_settings->send_report: %d",clam_settings->send_report);
	TRACE(TRACE_DEBUG,"clam_settings->add_header: %d",clam_settings->add_header);
	TRACE(TRACE_DEBUG,"clam_settings->header_name: %s",clam_settings->header_name);
	
	return 0;
}

int load(SETTINGS *settings, MAILCONN *mconn) {
	int fd_socket, errno, ret, fh;
	struct sockaddr_in sa;
	int bytes = 0;
	uint32_t conv;
	char r_buf[BUFSIZE];
	char *transmit;
	CLAMAV_SETTINGS *clam_settings;
	clam_settings = g_slice_new(CLAMAV_SETTINGS);

	TRACE(TRACE_DEBUG,"clamav loaded");
	if (parse_clam_config(settings,clam_settings)!=0) 
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

	g_free(transmit);
	g_free(clam_settings->host); 
	g_slice_free(CLAMAV_SETTINGS,clam_settings);

	return 0;
}
