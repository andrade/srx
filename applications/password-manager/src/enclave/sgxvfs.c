// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT

#include <errno.h>
#include <time.h>

//#include <sgx_tprotected_fs.h>

#include "enclave_t.h"

#include "sqlite3.h"

#ifndef UNUSED_PARAMETER
#define UNUSED_PARAMETER(x) (void)(x)  // definition from sqlite3.c
#endif

/* --------[        sqlite3_io_methods declarations        ]-------- */

static int xClose(sqlite3_file *file);
static int xRead(sqlite3_file *file, void *buffer, int amount, sqlite3_int64 offset);
static int xWrite(sqlite3_file *file, const void *buffer, int amount, sqlite3_int64 offset);
static int xTruncate(sqlite3_file *file, sqlite3_int64 size);
static int xSync(sqlite3_file *file, int flags);
static int xFileSize(sqlite3_file *file, sqlite3_int64 *size);
static int xLock(sqlite3_file *file, int eFileLock);
static int xUnlock(sqlite3_file *file, int eFileLock);
static int xCheckReservedLock(sqlite3_file *file, int *isLocked);
static int xFileControl(sqlite3_file *file, int op, void *arg);
static int xSectorSize(sqlite3_file *file);
static int xDeviceCharacteristics(sqlite3_file *file);

/* --------[            sqlite3_vfs declarations            ]-------- */

static int xOpen(sqlite3_vfs *vfs, const char *zName, sqlite3_file *file, int flags, int *pOutFlags);
static int xDelete(sqlite3_vfs *vfs, const char *zName, int syncDir);
static int xAccess(sqlite3_vfs *vfs, const char *zName, int flags, int *hasPerm);
static int xFullPathname(sqlite3_vfs *vfs, const char *zName, int cap, char *zOut);
static int xRandomness(sqlite3_vfs *vfs, int len, char *buf);
static int xSleep(sqlite3_vfs *vfs, int microseconds);
static int xCurrentTime(sqlite3_vfs *vfs, double *time);
static int xGetLastError(sqlite3_vfs *vfs, int cap, char *output);
static int xCurrentTimeInt64(sqlite3_vfs *vfs, sqlite3_int64 *time);

/* --------[                                                ]-------- */

struct sgx_file {
	sqlite3_file base;
	//SGX_FILE *fp;
	//sgx_key_128bit_t sk;
};

static struct sqlite3_io_methods sgx_io_methods = {
	.iVersion = 1,
	.xClose = xClose,
	.xRead = xRead,
	.xWrite = xWrite,
	.xTruncate = xTruncate,
	.xSync = xSync,
	.xFileSize = xFileSize,
	.xLock = xLock,
	.xUnlock = xUnlock,
	.xCheckReservedLock = xCheckReservedLock,
	.xFileControl = xFileControl,
	.xSectorSize = xSectorSize,
	.xDeviceCharacteristics = xDeviceCharacteristics,

	.xShmMap = 0,
	.xShmLock = 0,
	.xShmBarrier = 0,
	.xShmUnmap = 0,

	.xFetch = 0,
	.xUnfetch = 0
};

static struct sqlite3_vfs sgx_vfs = {
	.iVersion = 1,
	.szOsFile = sizeof(struct sgx_file),
	.mxPathname = 259,  // max file name is 260 in SGX, SQLite adds 1 for NUL
	.pNext = 0,
	.zName = "sgx",
	.pAppData = 0,
	.xOpen = xOpen,
	.xDelete = xDelete,
	.xAccess = xAccess,
	.xFullPathname = xFullPathname,
	.xDlOpen = 0,
	.xDlError = 0,
	.xDlSym = 0,
	.xDlClose = 0,
	.xRandomness = xRandomness,
	.xSleep = xSleep,
	.xCurrentTime = xCurrentTime,
	.xGetLastError = xGetLastError,

	.xCurrentTimeInt64 = xCurrentTimeInt64,

	.xSetSystemCall = 0,
	.xGetSystemCall = 0,
	.xNextSystemCall = 0
};

/* --------                sqlite3_io_methods                -------- */

static int xClose(sqlite3_file *file)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	return SQLITE_INTERNAL;
}

static int xRead(sqlite3_file *file, void *buffer, int amount, sqlite3_int64 offset)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(buffer);
	UNUSED_PARAMETER(amount);
	UNUSED_PARAMETER(offset);
	return SQLITE_INTERNAL;
}

static int xWrite(sqlite3_file *file, const void *buffer, int amount, sqlite3_int64 offset)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(buffer);
	UNUSED_PARAMETER(amount);
	UNUSED_PARAMETER(offset);
	return SQLITE_INTERNAL;
}

static int xTruncate(sqlite3_file *file, sqlite3_int64 size)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(size);
	return SQLITE_INTERNAL;
}

static int xSync(sqlite3_file *file, int flags)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(flags);
	return SQLITE_INTERNAL;
}

static int xFileSize(sqlite3_file *file, sqlite3_int64 *size)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(size);
	return SQLITE_INTERNAL;
}

static int xLock(sqlite3_file *file, int eFileLock)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(eFileLock);
	return SQLITE_INTERNAL;
}

static int xUnlock(sqlite3_file *file, int eFileLock)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(eFileLock);
	return SQLITE_INTERNAL;
}

// check if file held by RESERVED lock by any process, set `result` accordingly
static int xCheckReservedLock(sqlite3_file *file, int *isLocked)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(isLocked);
	return SQLITE_INTERNAL;
}

static int xFileControl(sqlite3_file *file, int op, void *arg)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(op);
	UNUSED_PARAMETER(arg);
	return SQLITE_INTERNAL;
}

static int xSectorSize(sqlite3_file *file)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	return 512;
}

static int xDeviceCharacteristics(sqlite3_file *file)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(file);
	return SQLITE_IOCAP_ATOMIC | SQLITE_IOCAP_SAFE_APPEND;
}

/* --------                   sqlite3_vfs                   -------- */

static int xOpen(sqlite3_vfs *vfs, const char *zName, sqlite3_file *file, int flags, int *pOutFlags)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	UNUSED_PARAMETER(zName);
	UNUSED_PARAMETER(file);
	UNUSED_PARAMETER(flags);
	UNUSED_PARAMETER(pOutFlags);
	return SQLITE_INTERNAL;
}

static int xDelete(sqlite3_vfs *vfs, const char *zName, int syncDir)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	UNUSED_PARAMETER(zName);
	UNUSED_PARAMETER(syncDir);
	return SQLITE_INTERNAL;
}

static int xAccess(sqlite3_vfs *vfs, const char *zName, int flags, int *hasPerm)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	UNUSED_PARAMETER(zName);
	UNUSED_PARAMETER(flags);
	UNUSED_PARAMETER(hasPerm);
	return SQLITE_INTERNAL;
}

static int xFullPathname(sqlite3_vfs *vfs, const char *zName, int cap, char *zOut)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	sqlite3_snprintf(cap, zOut, "%s", zName);
	return SQLITE_OK;
}

// returns amount of random bytes written to `buf` (expected `len` bytes)
static int xRandomness(sqlite3_vfs *vfs, int len, char *buf)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	if (sgx_read_rand(buf, len)) {
		return SQLITE_ERROR;
	}
	return len;
}

//TODO  Used by memdb.c
static int xSleep(sqlite3_vfs *vfs, int microseconds)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	UNUSED_PARAMETER(microseconds);
	return SQLITE_INTERNAL;
}

//TODO  Used by memdb.c
// current time as a Julian Day Number
static int xCurrentTime(sqlite3_vfs *vfs, double *time)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	// UNUSED_PARAMETER(time);
	// return SQLITE_INTERNAL;

	sqlite3_int64 n;

	if (xCurrentTimeInt64(0, &n)) {
		return SQLITE_INTERNAL;
	}
	*time = n / 86400000.0;

	return SQLITE_OK;
}

static int xGetLastError(sqlite3_vfs *vfs, int cap, char *output)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	UNUSED_PARAMETER(cap);
	UNUSED_PARAMETER(output);
	return errno;
}

static int xCurrentTimeInt64(sqlite3_vfs *vfs, sqlite3_int64 *time)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(vfs);
	// UNUSED_PARAMETER(time);
	// return SQLITE_INTERNAL;

	int retval;

	if (sqlite3_ocall_time64(&retval, (long long *) &time)) {
		fprintf(stderr, "sqlite3_ocall_time64 failure\n");
		return SQLITE_INTERNAL;
	}
	if (retval) {
		fprintf(stderr, "error finding current time\n");
		return SQLITE_INTERNAL;
	}

	return retval;
}

/* --------                    SQLite OS                    -------- */

int sqlite3_os_init(void)
{
	printf("sgxvfs called (%s)\n", __func__);
	UNUSED_PARAMETER(&sgx_io_methods);
	return sqlite3_vfs_register(&sgx_vfs, 1);
}

int sqlite3_os_end(void)
{
	printf("sgxvfs called (%s)\n", __func__);
	return sqlite3_vfs_unregister(&sgx_vfs);
}
