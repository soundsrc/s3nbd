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

#include <ne_session.h>
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

	ne_session *session;
	int session_count;
	S3KeyInfo key_info;
} S3;


#define AWS_S3_URL "s3.amazonaws.com"

/**
 * Signs the provided string with the AWS id and secret
 * @param s3 Pointer to S3 object
 * @param string String to sign
 * @return Returns the signed string in a allocated buffer. Use free() to free buffer after use.
 */
char *s3_sign_string(const S3 *s3,const char *string);

/**
 * Create a new S3 object
 * @param access_id  AWS access id
 * @param secret_key AWS secret key
 * @return Returns a new S3 object
 */
S3 *new_S3(const char *access_id,const char *secret_key);


/**
 * Frees memory associated with the S3 object
 * @param s3 Pointer to S3 object
 */
void free_S3(S3 *s3);


/**
 * Begins a new session
 * @param s3 Pointer to S3 object
 */
void s3_begin_session(S3 *s3);

/**
 * Ends a session
 * @param s3 Pointer to S3 object
 */
void s3_end_session(S3 *s3);

/**
 * Creates a bucket
 * @param s3 Pointer to S3 object
 * @param bucket Name of the bucket to create
 * @return Returns 0 if bucket was created, -1 on error
 */
int s3_create_bucket(S3 *s3,const char *bucket);

/**
 * Deletes a bucket
 * @param s3 Pointer to S3 object
 * @param bucket Name of bucket to delete
 * @return Returns 0 if bucket was removed, -1 on error
 */
int s3_delete_bucket(S3 *s3,const char *bucket);

/**
 * Gets a list of keys in the bucket. Keys are provided through a callback
 * function.
 * @param s3 Pointer to S3 object
 * @param bucket Bucket name
 * @param prefix Prefix for listing keys, or NULL
 * @param marker Marker for listing keys starting at marker, or NULL
 * @param max_keys Maximum number of keys to list, or -1.
 * @param delimiter Delimiter used to group keys between prefix and delimiter into 1 entry, or NULL
 * @param key_info_cb Pointer to a \a KeyInfoCallback structure which is called per key
 * @return Returns 0 or -1 on error
 */
int s3_get_bucket(S3 *s3,const char *bucket,
	const char *prefix,const char *marker,int max_keys,const char *delimiter,
	const S3KeyInfoCallback *key_info_cb);


/**
 * Stores data to S3
 * @param s3 Pointer to S3 object
 * @param bucket Bucket name
 * @param key Key name
 * @param content_type Content type
 * @param content_length Content length
 * @param rcb Pointer to \a S3ReadCallback structure used to feed data to server
 * @return Returns 0 or -1 on error
 */
int s3_put_object(S3 *s3,const char *bucket,const char *key,const char *content_type,int content_length,const S3ReadCallback *rcb);

/**
 * Retrieves data from S3
 * @param s3 Pointer to S3 object
 * @param bucket Bucket name
 * @param key Key name
 * @param wcb Pointer to \a S3WriteCallback structure used to save the retrieved data
 * @return Return 0 or -1 on error
 */
int s3_get_object(S3 *s3,const char *bucket,const char *key,const S3WriteCallback *wcb);

/**
 * Performs a GET on an object but does not retrieve the body
 * @param s3 Pointer to S3 object
 * @param bucket Bucket name
 * @param key Key name
 * @param oi Pointers to \a S3ObjectInfo to store information about the object
 * @return Returns 0 or -1 on error
 */
int s3_head_object(S3 *s3,const char *bucket,const char *key,S3ObjectInfo *oi);

/**
 * Deletes an object
 * @param s3 Pointers to S3 object
 * @param bucket Bucket name
 * @param key Key name
 * @return Returns 0 or -1 on error
 */
int s3_delete_object(S3 *s3,const char *bucket,const char *key);

/**
 * Convenience function for using a file as a read callback
 * @param fp Pointer to FILE*
 * @return Returns a \a S3ReadCallback
 */
const S3ReadCallback *s3_file_rcb(FILE *fp);

/**
 * Convenience function for using a file as a write callback
 * @param fp Pointer to FILE*
 * @return Returns a \a S3writeCallback
 */
const S3WriteCallback *s3_file_wcb(FILE *fp);

/**
 * Convenience function for using a buffer as a read callback
 * @param mem Pointer to buffer
 * @param len Length of the buffer
 * @return Returns a \a S3ReadCallback
 */
const S3ReadCallback *s3_mem_rcb(void *mem,unsigned int len);

/**
 * Convenience function for using a buffer as a write callback
 * @param mem Pointer to buffer
 * @param len Length of the buffer
 * @return Returns a \a S3WriteCallback
 */
const S3WriteCallback *s3_mem_wcb(void *mem,unsigned int len);

#endif
