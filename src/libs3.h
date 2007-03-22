/*
	Amazon S3 library
	Copyright (C) 2007 Sound <sound@sagaforce.com>

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#ifndef __libs3_h
#define __libs3_h

#include <ne_string.h>

#define MAX_BUCKET_NAME 255
#define MAX_KEY_NAME 1024

typedef struct _S3ReadCallback
{
	ssize_t (*callback)(void *,char *,size_t);
	void *userdata;
} S3ReadCallback;

typedef struct _S3WriteCallback
{
	ssize_t (*callback)(void *,char *,size_t);
	void *userdata;
} S3WriteCallback;

typedef struct _S3KeyInfo S3KeyInfo;
typedef struct _S3KeyInfoCallback {
	void (*callback)(void *,const S3KeyInfo *);
	void *userdata;
} S3KeyInfoCallback;

struct _S3KeyInfo
{
	const char *name;
	unsigned int last_modified;
	const char *etag;
	unsigned int size;
	const char *storage_class;
	const char *owner_id;
	const char *owner_display_name;

	// private interface
	const S3KeyInfoCallback *key_info_cb;

	ne_buffer *nb_name;
	ne_buffer *nb_etag;
	ne_buffer *nb_storage_class;
	ne_buffer *nb_owner_id;
	ne_buffer *nb_owner_display_name;
};

typedef struct _S3ObjectInfo
{
	char etag[80];
	char content_type[32];
	unsigned int content_length;
} S3ObjectInfo;

typedef struct _S3
{
	char access_id[64];
	char secret_key[64];
	char error[512];

	S3KeyInfo key_info;
} S3;


#define AWS_S3_URL "s3.amazonaws.com"

char *s3_sign_string(const S3 *s3,const char *string);
S3 *new_S3(const char *access_id,const char *secret_key);
void free_S3(S3 *s3);
int init_s3(S3 *s3,const char *access_id,const char *secret_key);
int s3_create_bucket(S3 *s3,const char *bucket);
int s3_delete_bucket(S3 *s3,const char *bucket);
int s3_get_bucket(S3 *s3,const char *bucket,
	const char *prefix,const char *marker,int max_keys,const char *delimiter,
	const S3KeyInfoCallback *key_info_cb);
int s3_put_object(S3 *s3,const char *bucket,const char *key,const char *content_type,int content_length,const S3ReadCallback *rcb);
int s3_get_object(S3 *s3,const char *bucket,const char *key,const S3WriteCallback *wcb);
int s3_head_object(S3 *s3,const char *bucket,const char *key,S3ObjectInfo *oi);
int s3_delete_object(S3 *s3,const char *bucket,const char *key);

const S3ReadCallback *s3_file_rcb(FILE *fp);
const S3WriteCallback *s3_file_wcb(FILE *fp);
const S3ReadCallback *s3_mem_rcb(void *mem,unsigned int len);
const S3WriteCallback *s3_mem_wcb(void *mem,unsigned int len);

#endif
