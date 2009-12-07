/*
 * spmfilter clamav plugin
 * by Axel Steiner <ast@treibsand.com>
 */

#define _GNU_SOURCE

#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <spmfilter.h>

#define THIS_MODULE "clamav"

#define STREAM "STREAM\r\n"

typedef struct {
	char *host;
	char *port;
	int max_scan_size;
	gboolean add_header;
	gboolean send_report;
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

	clam_settings->port = g_key_file_get_string(keyfile,"clamav","port",NULL);
	if (!clam_settings->port)
		clam_settings->port = g_strdup("3310");
	
	clam_settings->max_scan_size = g_key_file_get_integer(keyfile,"clamav","max_scan_size",NULL);
	if (!clam_settings->max_scan_size)
		clam_settings->max_scan_size = 5242880;
	
	clam_settings->send_report = g_key_file_get_boolean(keyfile,"clamav","send_report",NULL);
	if (!clam_settings->send_report)
		clam_settings->send_report = FALSE;
	
	clam_settings->add_header = g_key_file_get_boolean(keyfile,"clamav","add_header",NULL);
	if (!clam_settings->add_header)
		clam_settings->add_header = FALSE;
	
	TRACE(TRACE_DEBUG,"clam_settings->host: %s",clam_settings->host);
	TRACE(TRACE_DEBUG,"clam_settings->port: %s",clam_settings->port);
	TRACE(TRACE_DEBUG,"clam_settings->max_scan_size: %d",clam_settings->max_scan_size);
	TRACE(TRACE_DEBUG,"clam_settings->send_report: %d",clam_settings->send_report);
	TRACE(TRACE_DEBUG,"clam_settings->add_header: %d",clam_settings->add_header);
	
	return 0;
}

int load(SETTINGS *settings, MAILCONN *mconn) {
	int smaster, sdata, errno;
	struct sockaddr_in sa_in;
	struct addrinfo hints, *res;
	char *line;
	char *port_s;
	GIOChannel *master, *data, *msg;
	GError *error = NULL;
	gsize length;
	char *result;
	CLAMAV_SETTINGS *clam_settings;
	clam_settings = g_slice_new(CLAMAV_SETTINGS);

	TRACE(TRACE_DEBUG,"clamav loaded");
	if (parse_clam_config(settings,clam_settings)!=0) 
		return -1;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((errno = getaddrinfo(clam_settings->host, clam_settings->port, &hints, &res)) != 0) {
		TRACE(TRACE_ERR,"getaddrinfo(%s:%s): %s",
			clam_settings->host,clam_settings->port,gai_strerror(errno));
		return -1;
	}

	TRACE(TRACE_DEBUG, "connecting to [%s] on port [%s]",clam_settings->host,clam_settings->port);
	while(res) {
		if ((smaster = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			TRACE(TRACE_ERR,"socket(): %s",strerror(errno));
			return -1;
		}
		
		if (connect(smaster, res->ai_addr, sizeof(struct sockaddr)) == -1) {
			struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
			TRACE(TRACE_ERR, "connect(%s:%d): %s", 
				inet_ntoa(sa->sin_addr), (int)ntohs(sa->sin_port),
				strerror(errno));
			res = res->ai_next;
			close(smaster);
		} else {
			break;
		}
	}

	if (res == NULL) {
		TRACE(TRACE_ERR, "unable to connect to %s", clam_settings->host);
		return -1;
	}

	master = g_io_channel_unix_new(smaster);
	g_io_channel_set_encoding(master,NULL,NULL);
	if (g_io_channel_write_chars(master, STREAM, -1, NULL, &error) != G_IO_STATUS_NORMAL) {
		TRACE(TRACE_ERR, "stream write failed: %s", error->message);
		g_io_channel_shutdown(master,TRUE,NULL);
		g_io_channel_unref(master);
		close(smaster);
		return -1;
	} else {
		g_io_channel_flush(master,NULL);
	}

	if (g_io_channel_read_line(master,&line,NULL,NULL,&error) != G_IO_STATUS_NORMAL) {
		TRACE(TRACE_ERR, "stream read failed: %s", error->message);
		return -1;
	}

	port_s = get_substring("^PORT\\s(.*)$",line,1);
	if (port_s == NULL) {
		TRACE(TRACE_ERR, "got no data port!");
		return -1;
	}
	
	TRACE(TRACE_DEBUG, "using port [%s] as clamav data port",port_s);
	
	memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
	sa_in.sin_port = htons(strtoul(port_s, NULL, 10));
	sa_in.sin_family = AF_INET;

	if ((sdata = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		TRACE(TRACE_ERR, "socket(): %s", strerror(errno));
		g_io_channel_shutdown(master,TRUE,NULL);
		g_io_channel_unref(master);
		close(smaster);
		return -1;
	}
	
	TRACE(TRACE_DEBUG, "connecting to [%s] on port [%s]",clam_settings->host,port_s);
	sa_in.sin_port = htons(strtoul(port_s, NULL, 10));
	if (connect(sdata, (struct sockaddr *)&sa_in, sizeof(struct sockaddr_in)) == -1) {
		TRACE(TRACE_ERR, "connect2(): %s\n", strerror(errno));
		g_io_channel_shutdown(master,TRUE,NULL);
		g_io_channel_unref(master);
		close(smaster);
		return -1;
	}

	if ((msg = g_io_channel_new_file(mconn->queue_file, "r",&error)) == NULL) {
		TRACE(TRACE_ERR, "error reading queue file: %s",error->message);
		close(sdata);
		g_io_channel_shutdown(master,TRUE,NULL);
		g_io_channel_unref(master);
		close(smaster);
		return -1;
	}
	g_io_channel_set_encoding(msg,NULL,NULL);
	data = g_io_channel_unix_new(sdata);
	g_io_channel_set_encoding(data,NULL,NULL);

	while (g_io_channel_read_line(msg,&line,&length,NULL,NULL) == G_IO_STATUS_NORMAL) {
		if (g_io_channel_write_chars(data,line,length,NULL,&error) != G_IO_STATUS_NORMAL) {
			TRACE(TRACE_ERR, "write to data stream failed: %s",error->message);
			g_io_channel_shutdown(data,TRUE,NULL);
			g_io_channel_unref(data);
			g_io_channel_shutdown(msg,TRUE,NULL);
			g_io_channel_unref(msg);
			close(sdata);
			g_io_channel_shutdown(master,TRUE,NULL);
			g_io_channel_unref(master);
			close(smaster);
			return -1;
		} 
	}
	g_io_channel_flush(master,NULL);

	g_io_channel_shutdown(data,TRUE,NULL);
	g_io_channel_unref(data);
	g_io_channel_shutdown(msg,TRUE,NULL);
	g_io_channel_unref(msg);
	close(sdata);

	if (g_io_channel_read_line(master,&line,NULL,NULL,&error) != G_IO_STATUS_NORMAL) {
		TRACE(TRACE_ERR, "stream read failed: %s", error->message);
		return -1;
	}

	g_io_channel_shutdown(master,TRUE,NULL);
	g_io_channel_unref(master);
	close(smaster);

	result = get_substring("^stream:\\s(.*)$",line,1);
	if (port_s == NULL) {
		TRACE(TRACE_ERR, "got no result on port [%s]",port_s);
		return -1;
	}
	
	TRACE(TRACE_DEBUG,"ClamAV result [%s]",result);
	
	if (line != NULL)
		g_free(line);
	
	g_free(clam_settings->host); 
	g_slice_free(CLAMAV_SETTINGS,clam_settings);

	return 0;
}
