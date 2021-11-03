// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "sqlite3.h"
#include "entry.h"
#include "db.h"
#include "utils.h"

#include "enclave_t.h"

// #include "../csysperf.h"
// Copied over from csysperf.h
enum {
	MICRO = 0,
	MAIN,
	ENCLAVE_C,
	ENCLAVE_D,
	// SERVER_C,
	// SERVER_D,
	INIT_DB_N_SAVE_FUNC,
	LOAD_N_ADD_ENTRY_N_SAVE_FUNC,
	LOAD_N_LIST_ALL_FUNC,
	LOAD_N_LIST_ID_FUNC,
	DB_GET_ONE,
	DB_INTEGRITY_CHECK,
	S3_EXEC,
	ADD_ENTRY_OP_INSERT_QUERY,
	LIST_ALL_OP_SELECT_QUERY,
	LIST_ONE_OP_SELECT_QUERY,
	COMPUTE_SECRET,
	LOAD_DATA,
	SAVE_DATA,
	DB_OPEN,
	DB_CLOSE,
	DB_LOAD,
	DB_SAVE,
	CSP_LAST // CSP_LAST is the length of the array; leave it in this position
};

// secret key used to encrypt and decrypt the Titan database
static uint8_t secret_key[16] = {0};

/* sqlite callbacks */
static int cb_check_integrity(void *notused, int argc, char **argv, char **column_name);
static int cb_get_by_id(void *entry, int argc, char **argv, char **column_name);
static int cb_list_all(void *entry, int argc, char **argv, char **column_name);
// static int cb_find(void *entry, int argc, char **argv, char **column_name);

static void register_vfs()
{
    // re-register memdb as default (`sgxvfs` is incomplete, not used)
    if (sqlite3_vfs_register(sqlite3_vfs_find("memdb"), 1)) {
        printf("re-registering memdb failure\n");
        abort();
    }
    printf("re-registered memdb as default\n");
}

/**
** Sets the secret key global variable.
** Returns zero on success.
**/
static int compute_srx_secret(const char *db_path)
{
    static bool has_been_computed = false;
    //printf("has been computed = %s\n", has_been_computed ? "true" : "false");

	// bench: comment this out to force key recomputation
    if (has_been_computed)
        return 0;

    // salt to derive the secret key (SRX)
    const uint8_t salt[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
    };

    char srx_path[260] = {0};
    compute_srx_path(db_path, srx_path, sizeof srx_path);

    srx_status xs = ecall_srx_get_sk(srx_path,
            salt, sizeof salt,
            secret_key, sizeof secret_key, 0);
    if (xs) {
        fprintf(stderr, "Could not retrieve secret key (SRX)\n");
        return 1;
    }

    has_been_computed = true;

    return 0;
}

// load from `path` into `db`
// returns zero on success
static int db_load(const char *path, sqlite3 *db, int read_only)
{
    if (compute_srx_secret(path)) {
        return 1;
    }

    unsigned char *data = NULL;
    size_t size = 0;
    if (titan_load_data(path, secret_key, (uint8_t **) &data, &size)) {
        fprintf(stderr, "error loading databse from disk\n");
        return 1;
    }

    // buffer freed automatically on close; allocate with SQLite functions
    unsigned flags = SQLITE_DESERIALIZE_FREEONCLOSE;

    // increase database buffer on demand, instead of allocating larger one
    flags |= SQLITE_DESERIALIZE_RESIZEABLE;

    // for operations that do not require changing the database
    if (read_only) {
        flags |= SQLITE_DESERIALIZE_READONLY;
    }

    int rc = sqlite3_deserialize(db, "main", data, size, size, flags);
    if (rc) {
        fprintf(stderr, "could not deserialize the database\n");
        return 1;
    }

    return 0;
}

// save from `db` into `path`
// can be used to flush DB to disk
// returns zero on success
static int db_save(const char *path, sqlite3 *db)
{
    if (compute_srx_secret(path)) {
        return 1;
    }

    sqlite3_int64 piSize;
    unsigned char *buf = sqlite3_serialize(db, "main", &piSize, 0);
    if (!buf) {
        fprintf(stderr, "serialization of DB failed\n");
        return 1;
    }
    fprintf(stdout, "DB serialized size is %"PRId64"\n", piSize);

    if (titan_save_data(path, secret_key, (const uint8_t *) buf, piSize)) {
        fprintf(stderr, "error flushing/saving database to disk\n");
        sqlite3_free(buf);
        return 1;
    }

    sqlite3_free(buf);

    return 0;
}

// open database from disk (if new, then not loaded from disk)
static int db_open(const char *path, sqlite3 **database,
        int is_new, int read_only)
{
    register_vfs();

    sqlite3 *db;
    // // bench, warm up
    // for (size_t i = 0; i < 100; i++) {
    //     sqlite3_open(path, &db);
    //     sqlite3_close(db);
    // }
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++) {
    //     sqlite3_open(path, &db);
    //     sqlite3_close(db);
    // }
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.002038457 [microbench] ADD
    // // bench, result x500 (-cache): 0.002046862 [microbench] ADD
    // // bench, result x500 (+cache): 0.002066209 [microbench] GET
    // // bench, result x500 (-cache): 0.002065338 [microbench] GET
	int rc = sqlite3_open(path, &db);
	if (rc) {
		printf("could not open DB at %s (%s)\n", path, sqlite3_errstr(rc));
		return 1;
	}
	printf("opened DB OK at %s\n", path);

    if (!is_new) {
        if (db_load(path, db, read_only)) {
            fprintf(stderr, "error pulling database from disk\n");
            sqlite3_close(db);
            return 1;
        }
    }

    *database = db;

    return 0;
}

//static int db_flush(const char *path, sqlite3 *db) // could be used after INIT

// Close database
// If `update_db` is set, then flush database to disk beforehand
static int db_close(const char *path, sqlite3 *db, int update_db)
{
    if (update_db && db_save(path, db)) {
        fprintf(stderr, "error pushing database to disk\n");
        return 1;
    }

    sqlite3_close(db);

    return 0;
}

/*Run integrity check for the database to detect
 *malformed and corrupted databases. Returns true
 *if everything is ok, false if something is wrong.
 */
static bool db_check_integrity(const char *path)
{
    sqlite3 *db;
    char *err = NULL;
    int retval;
    char *sql;

    // retval = sqlite3_open(path, &db);
    //
    // if(retval)
    // {
    //     fprintf(stderr, "Can't initialize: %s\n", sqlite3_errmsg(db));
    //     return false;
    // }
    if (db_open(path, &db, 0, 1)) {
        fprintf(stderr, "Failed to initialize database\n");
        return false;
    }

    sql = "pragma integrity_check;";

    retval = sqlite3_exec(db, sql, cb_check_integrity, 0, &err);

    if(retval != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", err);
        sqlite3_free(err);
        // sqlite3_close(db);
        db_close(path, db, 0);
        return false;
    }

    // sqlite3_close(db);
    db_close(path, db, 0);

    return true;
}

bool db_init_new(const char *path)
{
    sqlite3 *db;
    char *err = NULL;
    int rc;

    // int rc = sqlite3_open(path, &db);
    //
    // if(rc != SQLITE_OK)
    // {
    //     fprintf(stderr, "Failed to initialize database: %s\n", sqlite3_errmsg(db));
    //     sqlite3_close(db);
    //
    //     return false;
    // }
    if (db_open(path, &db, 1, 0)) {
        fprintf(stderr, "Failed to initialize database\n");
        return false;
    }

    char *query = "create table entries"
        "(id integer primary key, title text, user text, url text,"
        "password text, notes text,"
        "timestamp date default (datetime('now','localtime')));";

    rc = sqlite3_exec(db, query, 0, 0, &err);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: %s\n", err);
        sqlite3_free(err);
        // sqlite3_close(db);
        db_close(path, db, 0);

        return false;
    }

    // sqlite3_close(db);
    if (db_close(path, db, 1)) {
        fprintf(stderr, "Error closing database\n");
        return false;
    }

    return true;
}

bool db_insert_entry(Entry_t *entry)
{
    sqlite3 *db;
    char *err = NULL;
    char *path = NULL;
    int rc;

    path = read_active_database_path();

    if(!path)
    {
        fprintf(stderr, "Error getting database path\n");
        return false;
    }

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++)
    //     db_check_integrity(path);
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++)
    //     db_check_integrity(path);
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.072139174 [microbench]
    // // bench, result x500 (-cache): 0.217053628 [microbench]
    if(!db_check_integrity(path))
    {
        fprintf(stderr, "Corrupted database. Abort.\n");
        free(path);
        return 0;
    }

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++) {
	// 	db_open(path, &db, 0, 0); // Load DB for read-write
	// 	db_close(path, db, 1);    // Save DB, then close
	// }
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++) {
	// 	db_open(path, &db, 0, 0); // Load DB for read-write
	// 	db_close(path, db, 1);    // Save DB, then close
	// }
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.155365008 [microbench]
    // // bench, result x500 (-cache): 0.466306830 [microbench]

    // int rc = sqlite3_open(path, &db);
    //
    // if(rc != SQLITE_OK)
    // {
    //     fprintf(stderr, "Failed to initialize database: %s\n", sqlite3_errmsg(db));
    //     sqlite3_close(db);
    //     free(path);
    //
    //     return false;
    // }
    if (db_open(path, &db, 0, 0)) {
        fprintf(stderr, "Failed to initialize database\n");
        return false;
    }

    char *query = sqlite3_mprintf("insert into entries(title, user, url, password, notes)"
                                  "values('%q','%q','%q','%q','%q')",
                                  entry->title, entry->user, entry->url, entry->password,
                                  entry->notes);

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++)
    //     sqlite3_exec(db, query, NULL, 0, &err);
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++)
    //     sqlite3_exec(db, query, NULL, 0, &err);
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.010252853 [microbench]
    // // bench, result x500 (-cache): 0.010450558 [microbench]
    rc = sqlite3_exec(db, query, NULL, 0, &err);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: %s\n", err);
        sqlite3_free(err);
        sqlite3_free(query);
        // sqlite3_close(db);
        db_close(path, db, 0);
        free(path);

        return false;
    }

    sqlite3_free(query);
    // sqlite3_close(db);
    if (db_close(path, db, 1)) {
        fprintf(stderr, "Error closing database\n");
        return false;
    }
    free(path);

    return true;
}

// bool db_update_entry(int id, Entry_t *new_entry)
// {
//     sqlite3 *db;
//     char *err = NULL;
//     char *path = NULL;
//
//     path = read_active_database_path();
//
//     if(!path)
//     {
//         fprintf(stderr, "Error getting database path\n");
//         return false;
//     }
//
//     if(!db_check_integrity(path))
//     {
//         fprintf(stderr, "Corrupted database. Abort.\n");
//         free(path);
//
//         return 0;
//     }
//
//     int rc = sqlite3_open(path, &db);
//
//     if(rc != SQLITE_OK)
//     {
//         fprintf(stderr, "Failed to initialize database: %s\n", sqlite3_errmsg(db));
//         sqlite3_close(db);
//         free(path);
//
//         return false;
//     }
//
//     char *query = sqlite3_mprintf("update entries set title='%q',"
//                                   "user='%q',"
//                                   "url='%q',"
//                                   "password='%q',"
//                                   "notes='%q',timestamp=datetime('now','localtime') where id=%d;",
//                                   new_entry->title,
//                                   new_entry->user,
//                                   new_entry->url,
//                                   new_entry->password,
//                                   new_entry->notes,id);
//
//     rc = sqlite3_exec(db, query, NULL, 0, &err);
//
//     if(rc != SQLITE_OK)
//     {
//         fprintf(stderr, "Error: %s\n", err);
//         sqlite3_free(err);
//         sqlite3_free(query);
//         sqlite3_close(db);
//         free(path);
//
//         return false;
//     }
//
//     sqlite3_free(query);
//     sqlite3_close(db);
//     free(path);
//
//     return true;
// }

/*Get entry which has the wanted id.
 * Caller must free the return value.
 */
Entry_t *db_get_entry_by_id(int id)
{
    char *path = NULL;
    sqlite3 *db;
    int rc;
    char *query;
    char *err = NULL;
    Entry_t *entry = NULL;

    path = read_active_database_path();

    if(!path)
    {
        fprintf(stderr, "Error getting database path\n");
        return NULL;
    }

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++)
    //     db_check_integrity(path);
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++)
    //     db_check_integrity(path);
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.071740895 [microbench]
    // // bench, result x500 (-cache): 0.216688812 [microbench]
    if(!db_check_integrity(path))
    {
        fprintf(stderr, "Corrupted database. Abort.\n");
        free(path);

        return NULL;
    }

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++) {
    //         db_open(path, &db, 0, 1); // Load + read-only
    //         db_close(path, db, 0);    // close without saving
    // }
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++) {
    //         db_open(path, &db, 0, 1); // Load + read-only
    //         db_close(path, db, 0);    // close without saving
    // }
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.052288298 [microbench]
    // // bench, result x500 (-cache): 0.194656334 [microbench]

    // rc = sqlite3_open(path, &db);
    //
    // if(rc != SQLITE_OK)
    // {
    //     fprintf(stderr, "Error %s\n", sqlite3_errmsg(db));
    //     free(path);
    //
    //     return NULL;
    // }
    if (db_open(path, &db, 0, 1)) {
        fprintf(stderr, "Error opening database\n");
        free(path);
        return false;
    }

    entry = tmalloc(sizeof(struct _entry));

    query = sqlite3_mprintf("select id,title,user,url,password,notes,"
                            "timestamp from entries where id=%d;", id);

    /* Set id to minus one by default. If query finds data
     * we set the id back to the original one in the callback.
     * We can uses this to easily check if we have valid data in the structure.
     */
    entry->id = -1;

    // // bench, warm up
    // for (size_t i = 0; i < 100; i++) {
    //     rc = sqlite3_exec(db, query, cb_get_by_id, entry, &err);
    // }
    // ocall_csp_poke(MICRO, 0);
    // for (size_t i = 0; i < 500; i++) {
    //     rc = sqlite3_exec(db, query, cb_get_by_id, entry, &err);
    // }
    // ocall_csp_poke(MICRO, 1);
    // // bench, result x500 (+cache): 0.003792773 [microbench]
    // // bench, result x500 (-cache): 0.003770529 [microbench]
	// ocall_csp_poke(S3_EXEC, 0);
    rc = sqlite3_exec(db, query, cb_get_by_id, entry, &err);
	// ocall_csp_poke(S3_EXEC, 1);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: %s\n", err);
        sqlite3_free(err);
        sqlite3_free(query);
        free(path);

        return NULL;
    }

    sqlite3_free(query);
    // sqlite3_close(db);  // DB not changed, using standard close
    if (db_close(path, db, 0)) {
        fprintf(stderr, "Error closing database\n");
        free(path);
        return false;
    }
    free(path);

    return entry;
}

/* Returns true on success, false on failure.
 * Parameter changes is set to true if entry with given
 * id was found and deleted.
 */
bool db_delete_entry(int id, bool *changes)
{
    char *path = NULL;
    sqlite3 *db;
    int rc;
    char *query;
    char *err = NULL;
    int count;

    path = read_active_database_path();

    if(!path)
    {
        fprintf(stderr, "Error getting database path\n");
        return false;
    }

    if(!db_check_integrity(path))
    {
        fprintf(stderr, "Corrupted database. Abort.\n");
        free(path);

        return false;
    }

    // rc = sqlite3_open(path, &db);
    //
    // if(rc != SQLITE_OK)
    // {
    //     fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    //     free(path);
    //     return false;
    // }
    if (db_open(path, &db, 0, 0)) {
        fprintf(stderr, "Error opening database\n");
        return false;
    }

    query = sqlite3_mprintf("delete from entries where id=%d;", id);
    rc = sqlite3_exec(db, query, NULL, 0, &err);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: %s\n", err);
        sqlite3_free(err);
        sqlite3_free(query);
        // sqlite3_close(db);
        db_close(path, db, 0);
        free(path);

        return false;
    }

    count = sqlite3_changes(db);

    if(count > 0)
        *changes = true;

    sqlite3_free(query);
    if (count > 0) {
        // update database on disk
        if (db_close(path, db, 1)) {
            fprintf(stderr, "Error closing database\n");
            return false;
        }
    } else {
        // simply close, nothing to update
        db_close(path, db, 0);
    }

    free(path);

    return true;
}

/* Get latest count of entries pointed by count_latest.
 * -1 to get everything.
 */
Entry_t *db_get_list(int count_latest)
{
    char *path = NULL;
    char *err = NULL;
    sqlite3 *db;
    char *query = NULL;
    int rc;

    if(count_latest < 0 && count_latest != -1)
    {
        fprintf(stderr, "Invalid parameter <count>\n");
        return NULL;
    }

    path = read_active_database_path();

    if(!path)
    {
        fprintf(stderr, "Error getting database path\n");
        return NULL;
    }

    if(!db_check_integrity(path))
    {
        fprintf(stderr, "Corrupted database. Abort.\n");
        free(path);

        return NULL;
    }

    // int rc = sqlite3_open(path, &db);
    //
    // if(rc != SQLITE_OK)
    // {
    //     fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    //     sqlite3_close(db);
    //     free(path);
    //
    //     return NULL;
    // }
    if (db_open(path, &db, 0, 1)) {
        fprintf(stderr, "Failed to initialize database\n");
        return false;
    }

    /* Fill our list with dummy data */
    Entry_t *entry = entry_new("dummy", "dummy", "dummy", "dummy", "dummy");

    /* Get all data or a defined count */
    if(count_latest == -1)
        query = "select * from entries;";
    else
        query = sqlite3_mprintf("select * from entries order by datetime(timestamp) desc limit %d", count_latest);

    rc = sqlite3_exec(db, query, cb_list_all, entry, &err);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr, "Error: %s\n", err);
        sqlite3_free(err);

        if(count_latest != -1 && query != NULL)
            sqlite3_free(query);

        // sqlite3_close(db);
        db_close(path, db, 0);
        free(path);

        return NULL;
    }

    // sqlite3_close(db);  // DB not changed, using standard close
    db_close(path, db, 0);
    free(path);

    return entry;
}

// Entry_t *db_find(const char *search)
// {
//     char *path = NULL;
//     char *err = NULL;
//     sqlite3 *db;
//
//     path = read_active_database_path();
//
//     if(!path)
//     {
//         fprintf(stderr, "Error getting database path\n");
//         return NULL;
//     }
//
//     if(!db_check_integrity(path))
//     {
//         fprintf(stderr, "Corrupted database. Abort.\n");
//         free(path);
//
//         return NULL;
//     }
//
//     int rc = sqlite3_open(path, &db);
//
//     if(rc != SQLITE_OK)
//     {
//         fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
//         sqlite3_close(db);
//         free(path);
//
//         return NULL;
//     }
//
//     /* Fill our list with dummy data */
//     Entry_t *entry = entry_new("dummy", "dummy", "dummy", "dummy", "dummy");
//
//     /* Search the same search term from each column we're might be interested in. */
//     char *query = sqlite3_mprintf("select * from entries where title like '%%%q%%' "
//                                   "or user like '%%%q%%' "
//                                   "or url like '%%%q%%' "
//                                   "or notes like '%%%q%%';", search, search, search, search);
//
//     rc = sqlite3_exec(db, query, cb_find, entry, &err);
//
//     if(rc != SQLITE_OK)
//     {
//         fprintf(stderr, "Error: %s\n", err);
//         sqlite3_free(err);
//         sqlite3_free(query);
//         sqlite3_close(db);
//         free(path);
//
//         return NULL;
//     }
//
//     sqlite3_free(query);
//     sqlite3_close(db);
//     free(path);
//
//     return entry;
// }

static int cb_check_integrity(__attribute__((unused)) void *notused,
        int argc, char **argv, char **column_name)
{
    for(int i = 0; i < argc; i++)
    {
        if(strcmp(column_name[i], "integrity_check") == 0)
        {
            char *result = argv[i];

            if(strcmp(result, "ok") != 0)
                return 1;
        }
    }

    return 0;
}

static int cb_list_all(void *entry,
        __attribute__((unused)) int argc, char **argv,
        __attribute__((unused)) char **column_name)
{
    Entry_t *one_entry = entry_add(entry, argv[1], argv[2], argv[3], argv[4], argv[5]);
    one_entry->id = atoi(argv[0]);
    one_entry->stamp = strdup(argv[6]);

    return 0;
}

// static int cb_find(void *entry, int argc, char **argv, char **column_name)
// {
//     Entry_t *one_entry = entry_add(entry, argv[1], argv[2], argv[3], argv[4], argv[5]);
//     one_entry->id = atoi(argv[0]);
//     one_entry->stamp = strdup(argv[6]);
//
//     return 0;
// }

static int cb_get_by_id(void *entry,
        __attribute__((unused)) int argc, char **argv,
        __attribute__((unused)) char **column_name)
{
    /*Let's not allow NULLs*/
    if(argv[0] == NULL)
        return 1;
    if(argv[1] == NULL)
        return 1;
    if(argv[2] == NULL)
        return 1;
    if(argv[3] == NULL)
        return 1;
    if(argv[4] == NULL)
        return 1;
    if(argv[5] == NULL)
        return 1;
    // if(argv[6] == NULL)
    //     return 1;
    //FIXME  currently a bug where this field is always null

    ((Entry_t *)entry)->id = atoi(argv[0]);
    ((Entry_t *)entry)->title = strdup(argv[1]);
    ((Entry_t *)entry)->user = strdup(argv[2]);
    ((Entry_t *)entry)->url = strdup(argv[3]);
    ((Entry_t *)entry)->password = strdup(argv[4]);
    ((Entry_t *)entry)->notes = strdup(argv[5]);
    ((Entry_t *)entry)->stamp = sgx_strdup(argv[6]);
    ((Entry_t *)entry)->next = NULL;

    return 0;
}
