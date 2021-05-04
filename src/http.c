/* * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <ctype.h>
#include <jansson.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"


// Need macros here because of the sizeof
#define JSON_MAX 1024
#define HMAC_SECRET "not secret code"
#define crash_server(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define GOOD_USER "user0"
#define AUTH_TOKEN "auth_token"
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static bool free_the_cookies(cookies_t *cookies);
char * get_good_token(cookies_t *cookies);
static bool send_not_found(struct http_transaction *ta);
static bool is_jansson_loadable(const char *buf);
static bool is_proper_json(const char *buf);
static bool check_token_expiration(const char *auth_token, const unsigned char *secret, const char *user);
static bool valid_range(struct http_transaction *ta, size_t st_size);
static bool send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...);
char *token2claim(const char *token, const unsigned char *secret);
long int get_json_long(const char *buf, const char *key);
char *get_auth_token(char *cookie);
static bool check_token(const char *auth_token, const unsigned char *secret, const char *user);
static bool authentic(const char *username, const char *password);
const char *get_json_string(const char *buf, const char *key);
static bool send_cookie_and_claim(struct http_transaction *ta, const char *username);
static bool get_range(struct http_transaction *ta, char *field_value);
static bool handle_private(struct http_transaction *ta);
static bool ismp4(char *fname);

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2) {       // error, EOF, or less than 2 characters
	ta->client->closed = true;
        return false;
    }

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;
    if (strstr(req_path, "./") != NULL || strstr(req_path, "../") != NULL) {
	  if (!silent_mode) fprintf(stderr, "parse_request: req_path: %s\n", req_path);
	  send_not_found(ta);
//        send_error(ta, HTTP_BAD_REQUEST, "Authentication failed");
        return false;
    }

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
	if (!silent_mode) fprintf(stderr, "HEADER: %s\n", header);
        if (len == 2 && STARTS_WITH(header, CRLF)) {       // empty CRLF
            return true;
	}

        header[len-2] = '\0';
	if (!silent_mode) fprintf(stderr, "HEADER: %s\n", header);
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        char *field_value = strtok_r(NULL, " \t", &endptr);    // skip leading & trailing OWS
        if (!silent_mode) fprintf(stderr, "FIELD_VALUE: %s\n", field_value);

        if (field_name == NULL || field_value == NULL)
            return false;

        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. */
        if (!strcasecmp(field_name, "Connection")) {
            if (!strcasecmp(field_value, "close")) {
                ta->client->closed = true;
                http_add_header(&ta->resp_headers, "Connection", "close");
            }
        }
	if (!strcasecmp(field_name, "Range")) {
            if (get_range(ta, field_value))
                ta->ranged = true;
	}
	if (!strcasecmp(field_name, "Cookie")) {
	    do {
   	        if (!silent_mode) fprintf(stderr, "Cookie Header: %s\n", field_value);
                if (strstr(field_value, (const char *)AUTH_TOKEN) != NULL) {
    	            size_t siz = (size_t)strlen(field_value) + 1;
    	            ta->cookie = (char *)malloc(siz); // anti overflow
    	            strncpy(ta->cookie, field_value, siz);
		    ta->cookie[siz-1] = '\0';
                    cookies_t *cur;
                    cookies_t *next;
		    //add ta->cookie to ta->cookies
                    if (ta->cookies == NULL) {
                        ta->cookies = (cookies_t *)malloc(sizeof(cookies_t));
                        ta->cookies->cookie = ta->cookie;
		        ta->cookies->next = NULL;
                    } else {
                        cur = ta->cookies;
                        next = cur->next;
		        // find last entry
                        while (next != NULL) {
                            cur = cur->next;
                            next = cur->next;
                        }
    		        cur->next = (cookies_t *)malloc(sizeof (cookies_t));
		        cur->next->cookie = ta->cookie;
		        cur->next->next = NULL;
                    }

                }
	        if (!silent_mode) {
	            cookies_t *nxt = ta->cookies;
		    fprintf(stderr, "Cookie List:\n");
		    while (nxt != NULL) {
		        fprintf(stderr, "Cookie Entry:{%s}\n",nxt->cookie);
		        nxt = nxt->next;
		    }
	        }
                field_value = strtok_r(NULL, " \t", &endptr);
	    } while (field_value != NULL);

	}
    }
}

static bool 
get_range(struct http_transaction *ta, char *field_value)
{
    char *startp = strstr(field_value, "bytes");
    if (startp == NULL) {
	return false;
    }

    startp = strchr(field_value, '=');
    if (startp == NULL)
        return false;
    if (strlen(startp) <= 1)
        return false;
    startp++;
    if (!isdigit(*startp))
	return false;
    char **endptr = malloc(sizeof(char *));
    if (endptr == NULL)
        crash_server("malloc failed");
    ta->from = (off_t)strtoll(startp, endptr, 10);
    startp = *endptr;
    if (startp == NULL) {
        free(endptr);
        return false;
    }
    startp = strchr(startp, '-');
    if (startp == NULL) {
        free(endptr);
        return false;
    }
    if (strlen(startp) == 1) {
        ta->to = (off_t)-1;
        free(endptr);
	return true;
    }
    startp++;
    if (!isdigit(*startp)) {
        free(endptr);
        return false;
    }
    ta->to = (off_t)strtoll(startp, endptr, 10);
    if (ta->to == 0) {
	return false;
	free(endptr);
    }

    free(endptr);
    return true;
}
const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";
    if (!strcasecmp(suffix, ".mp4"))
	return "video/mp4";
    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    return "text/plain";
}
/*
static bool
handle_ranged_asset(struct http_transaction *ta, char *basedir, off_t from, off_t to)
{
            if (!silent_mode)    fprintf(stderr, "range: from %lu to %lu\n", (unsigned long)from, (unsigned long)to);
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    bool fellback = false;
fallen:
    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission Denied");
        else {
            if (!html5_fallback || fellback)
	        return send_not_found(ta);
	    else {
		snprintf(fname, sizeof(fname), "%s%s", basedir, "/index.html");
		fellback = true;
		goto fallen;
	    }
	}
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
    if (to > (st.st_size - 1)) {
        http_add_header(&ta->resp_headers, "Content-Range", "byte=*\/%ld",(long int)st.st_size);
        return false;
    }

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    http_add_header(&ta->resp_headers, "Content-Range", "bytes %d-%d/%d", (int)from, (int)to, (int)st.st_size -1);

    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}
*/


/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    bool fellback = false;
fallen:
//    if (!silent_mode) fprintf(stderr, "req_path:%s\nfname:%s\nbasedir:%s\n", req_path, fname, basedir);
    if (access(fname, R_OK)) {
        if (errno == EACCES) {
	    if (!silent_mode) fprintf(stderr, "no access to file %s\n", fname);
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission Denied.");
	} else {
isdirectory:
            if (!html5_fallback || fellback) {
	        return send_not_found(ta);
	    } else {
		snprintf(fname, sizeof(fname), "%s%s", basedir, "/index.html");
		fellback = true;
		goto fallen;
	    }
	}
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
    if (S_ISDIR(st.st_mode))    
        goto isdirectory;

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from = 0, to = st.st_size - 1;
    if (ta->ranged &&valid_range(ta, st.st_size)) {
        from = ta->from;
        to = ta-> to;
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %lld-%lld/%lld", (long long int)from, (long long int) to, (long long int)st.st_size);
        ta->resp_status = HTTP_PARTIAL_CONTENT;
    } else
	ta->ranged = false;


    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}

static bool 
valid_range(struct http_transaction *ta, size_t st_size)
{
    if (ta->to == (off_t)-1)
        ta->to = (off_t)st_size - 1;
    if (ta->from < 0)
	return false;
    if (ta->to <= ta->from)
        return false;
    if (ta->to > (off_t)st_size - 1)
        return false;
    return true;
}

static bool
send_json_mp4(struct http_transaction *ta, char *basedir)
{
    
    DIR *dirp = opendir(basedir);
    if (dirp == NULL) {
        crash_server("error: opendir");
    }
    struct dirent *direntp = readdir(dirp);
    if (direntp == NULL) {
    	crash_server("error: readdir");
    }
    buffer_appendc(&ta->resp_body, '[');
    while (direntp != NULL) {
        struct stat statbuf;
        char fname[PATH_MAX];
        if (snprintf(fname, sizeof(fname), "%s/%s", basedir, direntp->d_name) < 0)
    	    crash_server("snprintf");
        if (stat(fname, &statbuf) != 0) {
            if (!silent_mode)
            direntp = readdir(dirp);
	            continue;
            //exit(EXIT_FAILURE);
        }
        if (ismp4(direntp->d_name)) {
	    char json_entry[JSON_MAX];
            snprintf(json_entry, sizeof(json_entry), "{\"size\":%d,\"name\":\"%s\"},",
	        (int)statbuf.st_size, direntp->d_name);
	    buffer_appends(&ta->resp_body, json_entry);
        }
    
        direntp = readdir(dirp);
    }
    /* remove trailing comma , */
    if (ta->resp_body.len > 1)
	    ta->resp_body.buf[ta->resp_body.len-1] = ']';
    else
        buffer_appendc(&ta->resp_body, ']');
    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-type", "application/json");
    send_response(ta);
    return true;
}


static bool 
ismp4(char *fname)
{
    return strcasecmp(guess_mime_type(fname), "video/mp4") == 0;
}

static bool 
check_token(const char *auth_token, const unsigned char *secret, const char *user)
{
    jwt_t *jwt_token;
    if (auth_token == NULL) {
	if(!silent_mode) fprintf(stderr, "check_token: auth_token == NULL\n");
        return false;
    }
    if (jwt_decode(&jwt_token, auth_token, secret, (int)strlen((const char *)secret)) != 0) {
	if (!silent_mode) fprintf(stderr, "jwt_decode: cannot decode token: %s\n", auth_token);
	return false;
    }
    if (!silent_mode) fprintf(stderr, "test_auth: AAAAB3NzaC1yc2EAAAADAQABAAABAQDPzpju2czXarQDvrw4UWLlnPbEhV45fblXKo0ixQSxw4+RyIwnOBwRXzKub6BNqw5lXQcezHuIeWLm7D11pXs4P68Aa38ky7uqxiD7LVA1+1FE337rpOhMKg+kIMbLTxfjIrHqHNzs9Zoy9i0Zm0nhZ/HMwLkJVFhD1pS6tv8Z1fNILVKjeW7L6/J28NaIRZvvZIFvzrmfK/IJOlJ6Eu2vQFFE46W8PQAgwZGcC+zH8E7ovz9q0GamutqudM7pZmxN2VoCpCbKvTYcZG82aO3R5j6RKrUPI84cW3MiUXTJaS7sCkDSYVUoHBKpJ8GVAtirrQoBFMR4aS9wvQbK4Kfv");
    const char *sub = jwt_get_grant(jwt_token, "sub");
    if (sub == NULL)  {
       if (!silent_mode) perror("jwt_get_grant");
    }
    unsigned long int exp = jwt_get_grant_int(jwt_token, "exp");
    if (exp == 0) {
        if (!silent_mode) perror("jwt_get_grant_int");
    }
    time_t now = time(NULL);
    if (now < 0) {
        if (!silent_mode) perror("time");
    }
    if (now > exp) {
	if (!silent_mode) fprintf(stderr, "check_token: token expired, auth_tokenk==%s exp==%lld\n", auth_token, (long long int)exp);
        return false;
    }


    if (strncmp(user, sub, (size_t)strlen(user)) != 0) {
        if (!silent_mode) fprintf(stderr, "check_token: invalid user %s\n", sub);
        return false;
    }
    return true;
}
static bool 
check_token_expiration(const char *auth_token, const unsigned char *secret, const char *user)
{
    jwt_t *jwt_token;
    if (auth_token == NULL)
        return false;
    if (jwt_decode(&jwt_token, auth_token, secret, (int)strlen((const char *)secret)) != 0) {
        if (!silent_mode) perror("jwt_decode");
	return false;
    }
    const char *sub = jwt_get_grant(jwt_token, "sub");
    if (sub == NULL)  {
       if (!silent_mode) perror("jwt_get_grant");
    }
    unsigned long int exp = jwt_get_grant_int(jwt_token, "exp");
    if (exp == 0) {
        if (!silent_mode) perror("jwt_get_grant_int");
    }
    time_t now = time(NULL);
    if (now < 0) {
        if (!silent_mode) perror("time");
    }
    if (!silent_mode) fprintf(stderr, "check_token_expiration: now == %lld, exp == %lld\n", (long long int)now, (long long int) exp);
    if (now > exp)
        return false;
    // skip username check
    /*
    if (strncmp(user, sub, (size_t)strlen(user)) != 0) {
        return false;
    }
    */
    return true;
}
static bool
handle_api(struct http_transaction *ta)
{
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    if (STARTS_WITH(req_path, "/api/video")) {
        if (ta->req_method == HTTP_GET) {
            return send_json_mp4(ta, server_root);
        }
    } else
    if (STARTS_WITH(req_path, "/api/login")) {
	    // /api/login/blah
	    int delim = req_path[sizeof("/api/login")-1];
            if(!isspace(delim) && delim != '\0')
               return send_not_found(ta);

        if (ta->req_method == HTTP_POST){
            char *buf = bufio_offset2ptr(ta->client->bufio, ta->req_body);
	    if (!is_jansson_loadable(buf)) {
	    if (!silent_mode) fprintf(stderr, "!is_jansson_loadble(buf): %s\n", buf);
            if (!silent_mode) fprintf(stderr, "proper json buf : %s\n", is_proper_json(buf) ? "true" : "false");
                return send_error(ta, HTTP_PERMISSION_DENIED, "Authentication failed");
	    }
            const char *username = get_json_string(buf, "username");
            const char *password = get_json_string(buf, "password");
	    if (username == NULL || password == NULL) {
                return send_error(ta, HTTP_BAD_REQUEST, "Authentication failed");
	    }
	    if (authentic(username, password))
                return send_cookie_and_claim(ta, username);
	    else {
		if (!silent_mode) fprintf(stderr, "!authentic, username:%spassword%s\n", username, password);
                return send_error(ta, HTTP_PERMISSION_DENIED, "Authentication failed");
	    }
//                return send_error(ta, HTTP_BAD_REQUEST, "Authentication Failed");
	} else if (ta->req_method == HTTP_GET){
    /* METHOD == GET */
		/*
	    char *auth_token = get_auth_token(ta->cookie);
            if (check_token(auth_token,
                (const unsigned char *)HMAC_SECRET,
                (const char *)GOOD_USER)) {
		*/
	    char *auth_token = NULL;
	    if ((auth_token=get_good_token(ta->cookies)) != NULL) {
                char *claim = token2claim(auth_token, (const unsigned char *)HMAC_SECRET);
            	ta->resp_status = HTTP_OK;
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                buffer_appends(&ta->resp_body, claim);
                send_response(ta);
                return true;
            } else {
               // buffer_appends(&ta->resp_body, "{}");
                return send_error(ta, HTTP_OK, "{}");
            }
	} else
            return send_error(ta, HTTP_NOT_IMPLEMENTED, "API not implemented");

        
        return send_error(ta, HTTP_PERMISSION_DENIED, "");
    }
//    return send_error(ta, HTTP_NOT_IMPLEMENTED, "API not implemented");
  return send_error(ta, HTTP_NOT_FOUND, "API not implemented");
}

static bool free_the_cookies(cookies_t *cookies)
{
    cookies_t *next = cookies;
    cookies_t *prev;
    while (next != NULL) {
	free(next->cookie);
	prev = next;
	next = next->next;
	free(prev);
    }
    return true;
}



// returns auth_token from the first good cookie
char *
get_good_token(cookies_t *cookies)
{
    while (cookies != NULL) {
        char *auth_token = get_auth_token(cookies->cookie);
        if (check_token(auth_token,
            (const unsigned char *)HMAC_SECRET,
            (const char *)GOOD_USER))
            return auth_token;
    }
    return NULL;

}

char *
token2claim(const char *token, const unsigned char *secret)
{

    jwt_t *token_jwt;
    int ret;
    ret = jwt_decode(&token_jwt, token, secret, (size_t)(strlen((const char *)secret) + 1));
    if (ret != 0)
        return NULL;
    return jwt_get_grants_json(token_jwt, NULL);
}
/* no error handling yet */
static bool 
send_cookie_and_claim(struct http_transaction *ta, const char *username)
{
    jwt_t *tkn;
    jwt_new(&tkn);
    jwt_add_grant(tkn, "sub", username);
    time_t now = time(NULL);
    jwt_add_grant_int(tkn, "iat", now);
    jwt_add_grant_int(tkn, "exp", now + token_expiration_time);
    jwt_set_alg(tkn, JWT_ALG_HS256, (unsigned char *)HMAC_SECRET, strlen(HMAC_SECRET));

    char *cookie = jwt_encode_str(tkn);
    char *claim = jwt_get_grants_json(tkn, NULL);
    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "application/json");
    http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/", cookie);
    buffer_appends(&ta->resp_body,claim);
    return send_response(ta);
}
static bool 
authentic(const char *username, const char *password)
{
    if (username == NULL || password == NULL)
        return false;
    const char correct_username[] = "user0";
    size_t username_len = (size_t)(strlen(correct_username) + 1);
    const char correct_password [] = "thepassword";
    size_t password_len = (size_t)(strlen(correct_password) + 1);
    if (strncmp(correct_username, username, username_len) == 0
            && strncmp(correct_password, password, password_len) == 0)
         return true;
    return false;
}

static bool 
is_jansson_loadable(const char *buf)
{
    json_error_t json_error;
//    json_t *json_buf = json_loads(buf,  JSON_DECODE_ANY|JSON_DISABLE_EOF_CHECK, &json_error);
    json_t *json_buf = json_loads(buf, JSON_DISABLE_EOF_CHECK, &json_error);
//    json_t *json_buf = json_loads(buf, 0, &json_error);
    return json_buf != NULL;
}
static bool 
is_proper_json(const char *buf)
{
    jwt_t *jwt;
    if (jwt_new(&jwt) != 0)
	    return false; // assume false if anything goes wrong
    return jwt_add_grants_json(jwt, buf) == 0;
}

const char *
get_json_string(const char *buf, const char *key)
{
    json_error_t json_error;
    json_t *json_buf = json_loads(buf, JSON_DISABLE_EOF_CHECK, &json_error);
    if (json_buf == NULL)
        return NULL;
    json_t *retval = json_object_get((const json_t *)json_buf, key);
    if (retval == NULL)
        return NULL;
    return (const char *)json_string_value(retval);
}
long int 
get_json_long(const char *buf, const char *key)
{
    json_error_t json_error;
    json_t *json_buf = json_loads(buf, JSON_DISABLE_EOF_CHECK, &json_error);
    if (json_buf == NULL)
        return 0;
    json_t *retval = json_object_get((const json_t *)json_buf, key);
    if (retval == NULL)
        return 0;
    return (long int)json_integer_value(retval);
}

/* return what follows to auth_token= in the cookie header
 *
 */
char *
get_auth_token(char *cookie)
{
    char *auth_token;
    /* coded this way to protect us from wrong evaluation order */
    if(cookie == NULL) 
	    return NULL;
    if((auth_token=strstr(cookie, "auth_token")) == NULL)
	    return NULL;
    if ((auth_token=strchr(auth_token, '=')) == NULL)
	    return NULL;
    if (strlen(auth_token) <= 1)
            return NULL;
    ++auth_token;
    char *endptr[1];
    char *ret = strtok_r(auth_token, "; ", endptr);
    if (ret == NULL)
        if (!silent_mode) fprintf(stderr, "get_auth_token: problem with strtok_r");
    return ret;
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    buffer_init(&ta.resp_headers, 1024);
    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    http_add_header(&ta.resp_headers, "Accept-Ranges", "bytes");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
//    if (!silent_mode) fprintf(stderr, "handle_transaction: req_path == %s\n", req_path);
    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta);
    } 
    else {
        bool has_access = true;
        if (STARTS_WITH(req_path, "/private")) {
	    if (!silent_mode) fprintf(stderr, "accessing /private \n");
            has_access = handle_private(&ta);
	    if (!silent_mode) fprintf(stderr, "/private has_access: %s\n", has_access ? "true" : "false");
        } 
        if (has_access) {
            if (ta.req_method == HTTP_GET) {
                rc = handle_static_asset(&ta, server_root);
            } else
                send_error(&ta, HTTP_PERMISSION_DENIED, "403 Forbidden");
        } else {
                send_error(&ta, HTTP_PERMISSION_DENIED, "403 Forbidden");
        }
    }

    // HTTP 1.0 closes connections after every transaction, no persistence
    if (ta.req_version == HTTP_1_0)
        ta.client->closed = true;

    free_the_cookies(ta.cookies);
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc;
}

static bool 
handle_private(struct http_transaction *ta)
{
    cookies_t *next = ta->cookies;
    while (next != NULL) {
        char *auth_token = get_auth_token(next->cookie);
//	if (!silent_mode) fprintf(stderr, "handle_private: auth_token: %s\n", auth_token);
        if (auth_token != NULL) {
            if (check_token(auth_token, (unsigned char *)HMAC_SECRET, (const char *)GOOD_USER)) {
                 if(check_token_expiration(auth_token, (unsigned char *)HMAC_SECRET, (const char *)GOOD_USER))
                    return true;
    	    }
        }
	next = next->next;
    }
    return false;
}
