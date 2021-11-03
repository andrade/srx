/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#ifndef __CMD_UI_H
#define __CMD_UI_H

#include <stdint.h>

void init_database(const char *path, int force, int auto_encrypt);
bool add_new_entry(int auto_encrypt);
// bool edit_entry(int id, int auto_encrypt);
bool remove_entry(int id, int auto_encrypt);
void list_by_id(int id, int show_password, int auto_encrypt);
void list_all(int show_password, int auto_encrypt, int latest_count);
// void find(const char *search, int show_password, int auto_encrypt);
// void find_regex(const char *regex, int show_password);
void show_current_db_path();
void set_use_db(const char *path);

// void show_latest_entries(int show_password, int auto_encrypt, int count);

bool decrypt_database(const char *path);
bool encrypt_database();

// bool encrypt_any_file(const char *path);
// bool decrypt_any_file(const char *path);
//
// bool encrypt_directory(const char *path);
// bool decrypt_directory(const char *path);

// path to save initialization data to
void srx_platform_init(const char *save_path);

// path to load initialization data of new platform from (!= from SRX state)
void srx_platform_add(const char *load_path);

// use list to find the list of platforms IDs in the group
void srx_platform_remove(uint64_t pid);

// lists the platform IDs of all platforms that have access to the data
void srx_platform_list();

#endif
