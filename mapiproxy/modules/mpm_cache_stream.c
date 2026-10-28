/*
   MAPI Proxy - Cache module

   OpenChange Project

   Copyright (C) Julien Kerihuel 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
   \file mpm_cache_stream.c

   \brief Storage routines for the cache module
 */

#include "mapiproxy/dcesrv_mapiproxy.h"
#include "mapiproxy/libmapiproxy/libmapiproxy.h"
#include "mapiproxy/modules/mpm_cache.h"
#include "libmapi/libmapi.h"
#include "libmapi/libmapi_private.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>

/* Require a private root owned by the service; children are opened relative to it. */
int mpm_cache_open_root(const struct mpm_cache *mpm)
{
	struct stat sb;
	int fd;

	if (mpm == NULL || mpm->dbpath == NULL) return -1;
	fd = open(mpm->dbpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) return -1;
	if (fstat(fd, &sb) != 0 || sb.st_uid != geteuid() || (sb.st_mode & 0077) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Open each path component without following links; create only regular private files. */
NTSTATUS mpm_cache_stream_open(struct mpm_cache *mpm, struct mpm_stream *stream)
{
	TALLOC_CTX *tmp;
	char *path, *relative, *part, *next, *save;
	struct stat sb;
	bool create;
	size_t root_length;
	int dirfd = -1, fd = -1, nextfd;
	FILE *fp;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	if (mpm == NULL || mpm->dbpath == NULL || stream == NULL || stream->fp != NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	tmp = talloc_new(stream);
	if (tmp == NULL) return NT_STATUS_NO_MEMORY;
	create = stream->filename == NULL;
	if (!create) {
		path = talloc_strdup(tmp, stream->filename);
	} else if (stream->message != NULL) {
		path = talloc_asprintf(tmp, "%s/0x%"PRIx64"/0x%"PRIx64".stream",
			mpm->dbpath, stream->message->FolderId, stream->message->MessageId);
	} else if (stream->attachment != NULL && stream->attachment->message != NULL) {
		path = talloc_asprintf(tmp, "%s/0x%"PRIx64"/0x%"PRIx64"/%"PRIu32".stream",
			mpm->dbpath, stream->attachment->message->FolderId,
			stream->attachment->message->MessageId, stream->attachment->AttachmentID);
	} else {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	if (path == NULL) { status = NT_STATUS_NO_MEMORY; goto done; }
	root_length = strlen(mpm->dbpath);
	while (root_length > 1 && mpm->dbpath[root_length - 1] == '/') root_length--;
	if (strncmp(path, mpm->dbpath, root_length) != 0 || path[root_length] != '/') {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	relative = talloc_strdup(tmp, path + root_length + 1);
	if (relative == NULL) { status = NT_STATUS_NO_MEMORY; goto done; }
	dirfd = mpm_cache_open_root(mpm);
	if (dirfd == -1) goto done;
	part = strtok_r(relative, "/", &save);
	if (part == NULL) goto done;
	while (part != NULL) {
		if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
		}
		next = strtok_r(NULL, "/", &save);
		if (next == NULL) {
			fd = openat(dirfd, part, (create ? O_RDWR | O_CREAT : O_RDONLY) |
				O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
			break;
		}
		if (create && mkdirat(dirfd, part, 0700) != 0 && errno != EEXIST) goto done;
		nextfd = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (nextfd == -1) goto done;
		if (fstat(nextfd, &sb) != 0 || sb.st_uid != geteuid() || (sb.st_mode & 0077) != 0) {
			close(nextfd);
			goto done;
		}
		close(dirfd);
		dirfd = nextfd;
		part = next;
	}
	if (fd == -1 || fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || sb.st_nlink != 1) goto done;
	if (create) {
		if (fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) goto done;
	} else if (sb.st_size != stream->StreamSize) {
		goto done;
	}
	fp = fdopen(fd, create ? "r+b" : "rb");
	if (fp == NULL) goto done;
	fd = -1;
	stream->fp = fp;
	stream->offset = 0;
	if (create) stream->filename = talloc_steal(stream, path);
	status = NT_STATUS_OK;

done:
	if (fd != -1) close(fd);
	if (dirfd != -1) close(dirfd);
	talloc_free(tmp);
	return status;
}


/**
   \details Close the filesystem stream

   \param stream pointer to the mpm_stream entry

   \return NT_STATUS_OK on success, otherwise NT_STATUS_NOT_FOUND
 */
NTSTATUS mpm_cache_stream_close(struct mpm_stream *stream)
{
	int ret;
	if (stream == NULL || stream->fp == NULL) return NT_STATUS_NOT_FOUND;
	ret = fclose(stream->fp);
	stream->fp = NULL;
	return ret == 0 ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}


/**
   \details Read input_size bytes from a local binary stream

   \param stream pointer to the mpm_stream entry
   \param input_size the number of bytes to read
   \param length output pointer to the length effectively read from the
   stream
   \param data output pointer to the binary data read from the stream

   \return NT_STATUS_OK
 */
NTSTATUS mpm_cache_stream_read(struct mpm_stream *stream, size_t input_size, size_t *length, uint8_t **data)
{
	size_t count;
	if (length == NULL) return NT_STATUS_INVALID_PARAMETER;
	*length = 0;
	if (stream == NULL || stream->fp == NULL || data == NULL ||
	    (input_size != 0 && *data == NULL) || stream->offset > stream->StreamSize) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	count = stream->StreamSize - stream->offset;
	if (count > input_size) count = input_size;
	if (count == 0) return NT_STATUS_OK;
	if ((off_t)stream->offset < 0 || (uintmax_t)(off_t)stream->offset != stream->offset ||
	    fseeko(stream->fp, stream->offset, SEEK_SET) != 0) return NT_STATUS_UNSUCCESSFUL;
	*length = fread(*data, 1, count, stream->fp);
	stream->offset += *length;
	return *length == count && !ferror(stream->fp) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}


/**
   \details Write length bytes to a local stream

   \param stream pointer to the mpm_stream entry
   \param length the data length to write to the stream
   \param data pointer to the data to write to the stream

   \return NT_STATUS_OK on success, otherwise NT_STATUS_UNSUCCESSFUL
 */
NTSTATUS mpm_cache_stream_write(struct mpm_stream *stream, uint16_t length, uint8_t *data)
{
	size_t written;
	if (stream == NULL || stream->fp == NULL || (length != 0 && data == NULL) ||
	    stream->offset > stream->StreamSize || length > stream->StreamSize - stream->offset) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (length == 0) return NT_STATUS_OK;
	if ((off_t)stream->offset < 0 || (uintmax_t)(off_t)stream->offset != stream->offset ||
	    fseeko(stream->fp, stream->offset, SEEK_SET) != 0) return NT_STATUS_UNSUCCESSFUL;
	written = fwrite(data, 1, length, stream->fp);
	stream->offset += written;
	return written == length && fflush(stream->fp) == 0 && !ferror(stream->fp)
		? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}


/**
   \details Rewind a stream to the beginning

   \param stream pointer to the mpm_stream entry

   \return NT_STATUS_OK on success
 */
NTSTATUS mpm_cache_stream_reset(struct mpm_stream *stream)
{
	if (stream == NULL || stream->fp == NULL) return NT_STATUS_INVALID_PARAMETER;
	if (fseeko(stream->fp, 0, SEEK_SET) != 0) return NT_STATUS_UNSUCCESSFUL;
	clearerr(stream->fp);
	stream->offset = 0;
	return NT_STATUS_OK;
}
