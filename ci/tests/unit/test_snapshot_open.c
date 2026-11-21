/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the exact production opener against real disposable filesystem
 * objects. Only nginx's API spelling and logging boundary are substituted.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef unsigned char u_char;
typedef int ngx_fd_t;
typedef struct stat ngx_file_info_t;
typedef int ngx_log_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;

#define NGX_WIN32 0
#define NGX_INVALID_FILE (-1)
#define NGX_FILE_ERROR (-1)
#define NGX_FILE_RDONLY O_RDONLY
#define NGX_FILE_OPEN 0
#define NGX_ENOENT ENOENT
#define NGX_LOG_WARN 4
#define ngx_errno errno
#define ngx_open_file_n "open()"
#define ngx_fd_info_n "fstat()"
#define ngx_is_file(fi) S_ISREG((fi)->st_mode)

static int last_fd = -1;
static int logs;
static int inject_stat_error;
static const char *message;

static int
test_open(u_char *path, int mode, int create, int file_access)
{
    last_fd = open((char *) path, mode | create, file_access);
    return last_fd;
}

static int
test_stat(int fd, struct stat *fi)
{
    if (inject_stat_error) {
        errno = EIO;
        return -1;
    }
    return fstat(fd, fi);
}

static void
test_log(int level, ngx_log_t *log, int err, const char *format, ...)
{
    (void) level;
    (void) log;
    (void) err;
    logs++;
    message = format;
}

#define ngx_open_file test_open
#define ngx_fd_info test_stat
#define ngx_close_file close
#define ngx_log_error test_log

#ifdef TEST_NO_NONBLOCK
#undef O_NONBLOCK
#endif
#ifdef TEST_NO_NOFOLLOW
#undef O_NOFOLLOW
#endif

/* The runner replaces this declaration with the exact production definition.
 * Keep this template valid C for analyzers without generated include files. */
/* SNAPSHOT_OPEN_BEGIN */
ngx_fd_t ngx_http_error_abuse_open_snapshot(ngx_str_t *path,
    ngx_file_info_t *fi, ngx_log_t *log);
/* SNAPSHOT_OPEN_END */

static void
require(int ok, const char *name, const char *assertion)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s: %s\n", name, assertion);
        exit(1);
    }
}

int
main(int argc, char **argv)
{
    ngx_str_t path;
    struct stat fi;
    int fd;
    char data[8];
    const char *name;

    if (argc != 3) {
        return 2;
    }
    name = argv[1];
    path.data = (u_char *) argv[2];
    path.len = strlen(argv[2]);
    inject_stat_error = strcmp(name, "fstat-error") == 0;
    fd = ngx_http_error_abuse_open_snapshot(&path, &fi, NULL);

    if (strcmp(name, "regular") == 0 || strcmp(name, "empty") == 0) {
        require(fd >= 0, name, "regular snapshot rejected");
        require(S_ISREG(fi.st_mode), name, "metadata is not regular");
        require(logs == 0, name, "regular open logged a warning");
        if (strcmp(name, "regular") == 0) {
            require(read(fd, data, sizeof(data)) == (ssize_t) sizeof(data),
                    name, "regular snapshot unreadable");
            require(memcmp(data, "NGEAB01", sizeof(data)) == 0,
                    name, "snapshot bytes changed");
        }
        require(close(fd) == 0, name, "close failed");
    } else {
        require(fd == NGX_INVALID_FILE, name, "nonregular snapshot accepted");
        if (strcmp(name, "missing") == 0) {
            require(logs == 0, name, "absent snapshot logged a warning");
        } else {
            require(logs == 1, name, "expected one rejection warning");
        }
        if (strcmp(name, "unsupported") == 0) {
            require(last_fd == -1, name, "unsupported platform opened input");
            require(message != NULL && strstr(message, "unsupported") != NULL,
                    name, "unsupported platform warning missing");
        }
        if (last_fd >= 0) {
            errno = 0;
            require(fcntl(last_fd, F_GETFD) == -1 && errno == EBADF,
                    name, "rejected descriptor leaked");
        }
    }
    printf("OK: %s\n", name);
    return 0;
}
