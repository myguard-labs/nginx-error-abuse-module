/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_WIN32)

#include <openssl/sha.h>

#include "ngx_http_error_abuse_win32.h"

typedef DWORD (WINAPI *ngx_http_error_abuse_final_path_pt)(
    HANDLE, LPWSTR, DWORD, DWORD);

static WCHAR *
ngx_http_error_abuse_win32_utf16(u_char *path, ngx_log_t *log)
{
    int     nchars;
    WCHAR  *wide;

    nchars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                 (char *) path, -1, NULL, 0);
    if (nchars == 0) {
        return NULL;
    }

    wide = ngx_alloc((size_t) nchars * sizeof(WCHAR), log);
    if (wide == NULL) {
        ngx_set_errno(NGX_ENOMEM);
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *) path, -1,
                            wide, nchars) == 0)
    {
        ngx_free(wide);
        return NULL;
    }

    return wide;
}

static ngx_int_t
ngx_http_error_abuse_win32_mutex_name(ngx_str_t *path, WCHAR *name,
    size_t name_cap, ngx_log_t *log)
{
    static const WCHAR  prefix[] = L"Global\\ngx_error_abuse_persist_";
    static const WCHAR  hex[] = L"0123456789abcdef";

    u_char   digest[SHA256_DIGEST_LENGTH];
    DWORD    final_len, full_len, got;
    HANDLE   dir;
    HMODULE  kernel32;
    size_t   i, leaf_len, parent_len, prefix_len, total;
    ngx_http_error_abuse_final_path_pt  final_path;
    WCHAR   *canonical, *final, *full, *leaf, *parent, *slash, *wide;

    wide = ngx_http_error_abuse_win32_utf16(path->data, log);
    if (wide == NULL) {
        return NGX_ERROR;
    }

    full_len = GetFullPathNameW(wide, 0, NULL, NULL);
    if (full_len == 0) {
        ngx_free(wide);
        return NGX_ERROR;
    }

    full = ngx_alloc(((size_t) full_len + 1) * sizeof(WCHAR), log);
    if (full == NULL) {
        ngx_free(wide);
        ngx_set_errno(NGX_ENOMEM);
        return NGX_ERROR;
    }

    got = GetFullPathNameW(wide, full_len + 1, full, NULL);
    ngx_free(wide);
    if (got == 0 || got > full_len) {
        ngx_free(full);
        return NGX_ERROR;
    }

    slash = NULL;
    for (i = 0; full[i] != L'\0'; i++) {
        if (full[i] == L'\\' || full[i] == L'/') {
            slash = &full[i];
        }
    }
    if (slash == NULL || slash[1] == L'\0') {
        ngx_free(full);
        ngx_set_errno(ERROR_BAD_PATHNAME);
        return NGX_ERROR;
    }

    leaf = slash + 1;
    leaf_len = i - (size_t) (leaf - full);
    parent_len = (size_t) (slash - full);
    if (parent_len == 2 && full[1] == L':') {
        parent_len++;
    }

    parent = ngx_alloc((parent_len + 1) * sizeof(WCHAR), log);
    if (parent == NULL) {
        ngx_free(full);
        ngx_set_errno(NGX_ENOMEM);
        return NGX_ERROR;
    }
    ngx_memcpy(parent, full, parent_len * sizeof(WCHAR));
    parent[parent_len] = L'\0';

    dir = CreateFileW(parent, FILE_READ_ATTRIBUTES,
                      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ngx_free(parent);
    if (dir == INVALID_HANDLE_VALUE) {
        ngx_free(full);
        return NGX_ERROR;
    }

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    final_path = kernel32 == NULL ? NULL
                 : (ngx_http_error_abuse_final_path_pt) (uintptr_t)
                   GetProcAddress(kernel32, "GetFinalPathNameByHandleW");
    if (final_path == NULL) {
        (void) CloseHandle(dir);
        ngx_free(full);
        ngx_set_errno(ERROR_PROC_NOT_FOUND);
        return NGX_ERROR;
    }

    final_len = final_path(dir, NULL, 0,
                           FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if (final_len == 0) {
        (void) CloseHandle(dir);
        ngx_free(full);
        return NGX_ERROR;
    }

    final = ngx_alloc(((size_t) final_len + 1) * sizeof(WCHAR), log);
    if (final == NULL) {
        (void) CloseHandle(dir);
        ngx_free(full);
        ngx_set_errno(NGX_ENOMEM);
        return NGX_ERROR;
    }

    got = final_path(dir, final, final_len + 1,
                     FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    (void) CloseHandle(dir);
    if (got == 0 || got > final_len) {
        ngx_free(final);
        ngx_free(full);
        return NGX_ERROR;
    }

    total = (size_t) got;
    canonical = ngx_alloc((total + 1 + leaf_len) * sizeof(WCHAR), log);
    if (canonical == NULL) {
        ngx_free(final);
        ngx_free(full);
        ngx_set_errno(NGX_ENOMEM);
        return NGX_ERROR;
    }
    ngx_memcpy(canonical, final, total * sizeof(WCHAR));
    ngx_free(final);
    if (total != 0 && canonical[total - 1] != L'\\') {
        canonical[total++] = L'\\';
    }
    ngx_memcpy(canonical + total, leaf, leaf_len * sizeof(WCHAR));
    total += leaf_len;
    ngx_free(full);

    for (i = 0; i < total; i++) {
        if (canonical[i] == L'/') {
            canonical[i] = L'\\';
        }
    }
    (void) CharLowerBuffW(canonical, (DWORD) total);

    if (SHA256((u_char *) canonical, total * sizeof(WCHAR), digest) == NULL) {
        ngx_free(canonical);
        ngx_set_errno(ERROR_INVALID_DATA);
        return NGX_ERROR;
    }
    ngx_free(canonical);

    prefix_len = (sizeof(prefix) / sizeof(prefix[0])) - 1;
    if (name_cap < prefix_len + SHA256_DIGEST_LENGTH * 2 + 1) {
        ngx_set_errno(ERROR_INSUFFICIENT_BUFFER);
        return NGX_ERROR;
    }
    ngx_memcpy(name, prefix, prefix_len * sizeof(WCHAR));
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        name[prefix_len + i * 2] = hex[digest[i] >> 4];
        name[prefix_len + i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    name[prefix_len + SHA256_DIGEST_LENGTH * 2] = L'\0';

    return NGX_OK;
}

ngx_int_t
ngx_http_error_abuse_win32_owner_try(
    ngx_http_error_abuse_win32_owner_t *owner, ngx_str_t *path,
    ngx_log_t *log)
{
    DWORD   rc;
    WCHAR   name[sizeof("Global\\ngx_error_abuse_persist_")
                 + SHA256_DIGEST_LENGTH * 2];

    if (owner->owned) {
        return NGX_OK;
    }
    if (owner->failed) {
        return NGX_ERROR;
    }

    if (owner->mutex == NULL) {
        if (ngx_http_error_abuse_win32_mutex_name(path, name,
                                                  sizeof(name)
                                                  / sizeof(name[0]),
                                                  log) != NGX_OK)
        {
            owner->failed = 1;
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "error_abuse could not derive persistence mutex "
                          "for \"%V\"", path);
            return NGX_ERROR;
        }

        owner->mutex = CreateMutexW(NULL, FALSE, name);
        if (owner->mutex == NULL) {
            owner->failed = 1;
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "error_abuse CreateMutexW() failed for \"%V\"",
                          path);
            return NGX_ERROR;
        }
    }

    rc = WaitForSingleObject(owner->mutex, 0);
    if (rc == WAIT_OBJECT_0 || rc == WAIT_ABANDONED) {
        owner->owned = 1;
        if (rc == WAIT_ABANDONED) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "error_abuse recovered abandoned persistence "
                          "mutex for \"%V\"", path);
        }
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "error_abuse acquired persistence ownership for \"%V\"",
                      path);
        return NGX_OK;
    }
    if (rc == WAIT_TIMEOUT) {
        return NGX_DECLINED;
    }

    owner->failed = 1;
    ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                  "error_abuse WaitForSingleObject() failed for \"%V\"",
                  path);
    return NGX_ERROR;
}

void
ngx_http_error_abuse_win32_owner_release(
    ngx_http_error_abuse_win32_owner_t *owner, ngx_log_t *log)
{
    if (owner->owned) {
        if (ReleaseMutex(owner->mutex) == 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "error_abuse ReleaseMutex() failed");
        }
        owner->owned = 0;
    }
    if (owner->mutex != NULL) {
        (void) CloseHandle(owner->mutex);
        owner->mutex = NULL;
    }
}

ngx_int_t
ngx_http_error_abuse_win32_socket_readable(ngx_socket_t fd, ngx_log_t *log)
{
    int  available;

    if (ngx_socket_nread(fd, &available) == -1) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_socket_errno,
                      ngx_socket_nread_n " failed");
        return NGX_ERROR;
    }

    return available > 0 ? NGX_OK : NGX_AGAIN;
}

ngx_fd_t
ngx_http_error_abuse_win32_create_temp(u_char *path, ngx_log_t *log)
{
    DWORD                 err;
    HANDLE                fd;
    PSECURITY_DESCRIPTOR  descriptor;
    SECURITY_ATTRIBUTES   attributes;
    WCHAR                *wide;

    descriptor = NULL;
    wide = ngx_http_error_abuse_win32_utf16(path, log);
    if (wide == NULL) {
        return NGX_INVALID_FILE;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, NULL))
    {
        ngx_free(wide);
        return NGX_INVALID_FILE;
    }

    attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    fd = CreateFileW(wide, GENERIC_WRITE,
                     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                     &attributes, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    err = GetLastError();
    LocalFree(descriptor);
    ngx_free(wide);

    if (fd == INVALID_HANDLE_VALUE && err == ERROR_FILE_EXISTS) {
        err = NGX_EEXIST;
    }
    ngx_set_errno(err);
    return fd;
}

ngx_int_t
ngx_http_error_abuse_win32_flush_file(ngx_fd_t fd)
{
    return FlushFileBuffers(fd) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
ngx_http_error_abuse_win32_replace(u_char *from, ngx_str_t *to,
    ngx_log_t *log)
{
    ngx_err_t  err;
    ngx_str_t  from_name;

    if (ngx_rename_file(from, to->data) != NGX_FILE_ERROR) {
        return NGX_OK;
    }

    err = ngx_errno;
    if (err != NGX_EEXIST && err != NGX_EEXIST_FILE) {
        return NGX_ERROR;
    }

    from_name.data = from;
    from_name.len = ngx_strlen(from);
    err = ngx_win32_rename_file(&from_name, to, log);
    if (err != 0) {
        ngx_set_errno(err);
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_http_error_abuse_win32_sync_parent(u_char *path, ngx_log_t *log)
{
    (void) path;
    (void) log;
}

ngx_uint_t
ngx_http_error_abuse_win32_interrupted(ngx_err_t err)
{
    (void) err;
    return 0;
}

#endif /* NGX_WIN32 */
