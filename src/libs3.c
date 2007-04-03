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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <ne_alloc.h>
#include <ne_string.h>
#include <ne_session.h>
#include <ne_request.h>
#include <ne_socket.h>
#include <ne_xml.h>
#include "libs3.h"

char *s3_sign_string(const S3 *s3,const char *string)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	if(!s3) return NULL;

	HMAC(EVP_sha1(),s3->secret_key,strlen(s3->secret_key),
		(unsigned char *)string,strlen(string),md,&md_len);
	return ne_base64(md,md_len);
}

static void s3_parse_xml_response(S3 *s3,ne_request *req,
							ne_xml_startelm_cb *startelm,
							ne_xml_cdata_cb *cdata,
							ne_xml_endelm_cb *endelm,
							void *userdata)
{
	char buffer[4096];
	size_t bytes_read;
	ne_xml_parser *xml;

	xml = ne_xml_create();
	ne_xml_push_handler(xml,startelm,cdata,endelm,userdata);

	while((bytes_read = ne_read_response_block(req,buffer,4096)) > 0) {
		if(ne_xml_parse(xml,buffer,bytes_read) != 0)
			strncpy(s3->error,ne_xml_get_error(xml),511);
	}
	ne_xml_parse(xml,buffer,0);
	ne_xml_destroy(xml);
}

int s3_xml_error_startelm(void *userdata, int parent,
							const char *nspace, const char *name,
							const char **atts) {
	if(strcmp(name,"Error") == 0) return 1;
	if(parent == 1 && strcmp(name,"Message") == 0) return 2;
	return 0;
}

int s3_xml_error_cdata(void *userdata, int state,
							const char *cdata, size_t len) {
	S3 *s3 = userdata;
	if(state == 2) {
		strncpy(s3->error,cdata,len < 511 ? len : 511);
		s3->error[len < 511 ? len : 511] = 0;
	}
	return 0;
}
// int s3_xml_error_endelm(void *userdata, int state,
//                              const char *nspace, const char *name) { }

int s3_handle_error_response(S3 *s3,ne_request *req)
{
	s3_parse_xml_response(s3,req,s3_xml_error_startelm,s3_xml_error_cdata,NULL,s3);
	return 0;
}

S3 *new_S3(const char *access_id,const char *secret_key)
{
	S3 *s3;

	if(!access_id) return NULL;
	if(!secret_key) return NULL;

	if(strlen(access_id) > 63) return NULL;
	if(strlen(secret_key) > 63) return NULL;

	s3 = (S3 *)calloc(1,sizeof(S3));
	if(!s3) {
		fprintf(stderr,"Could not create S3 object. Out of memory.\n");
		exit(1);
	}

	strcpy(s3->access_id,access_id);
	strcpy(s3->secret_key,secret_key);
	s3->error[0] = 0;

	s3->session = NULL;
	s3->session_count = 0;

	s3->key_info.nb_name = ne_buffer_create();
	s3->key_info.nb_etag = ne_buffer_create();
	s3->key_info.nb_storage_class = ne_buffer_create();
	s3->key_info.nb_owner_id = ne_buffer_create();
	s3->key_info.nb_owner_display_name = ne_buffer_create();

	ne_sock_init();

	return s3;
}

void free_S3(S3 *s3)
{
	if(s3) {
		ne_buffer_destroy(s3->key_info.nb_name);
		ne_buffer_destroy(s3->key_info.nb_etag);
		ne_buffer_destroy(s3->key_info.nb_storage_class);
		ne_buffer_destroy(s3->key_info.nb_owner_id);
		ne_buffer_destroy(s3->key_info.nb_owner_display_name);
		memset(s3->access_id,0,64);
		memset(s3->secret_key,0,64);
		ne_sock_exit();
		free(s3);
	}
}

void s3_begin_session(S3 *s3)
{
	if(s3) {
		if(s3->session_count == 0) s3->session = ne_session_create("http",AWS_S3_URL,80);
		s3->session_count++;
	}
}

void s3_end_session(S3 *s3)
{
	if(s3 && s3->session) {
		s3->session_count--;
		if(s3->session_count == 0) {
			ne_session_destroy(s3->session);
			s3->session = NULL;
		}
	}
}

static ne_request *s3_new_request(const S3 *s3,const char *method,const char *bucket,const char *key,const char *params,const char *content_type)
{
	ne_buffer *date, *signing_string, *request_str;
	ne_request *req;
	char *sig, *p;
	time_t t;

	if(!s3) return NULL;
	if(!method) return NULL;
	if(!bucket) return NULL;
	if(!s3->session) return NULL;

	// create some string buffers
	date = ne_buffer_create();
	signing_string = ne_buffer_create();
	request_str = ne_buffer_create();

	// get the time
	t = time(NULL);
	ne_buffer_zappend(date,asctime(gmtime(&t)));
	if(date->data[date->used - 2] == '\n')
		date->data[date->used - 2] = 0;
	ne_buffer_altered(date);

	// create request
	if(key) ne_buffer_concat(request_str,"/",bucket,"/",key,NULL);
	else ne_buffer_concat(request_str,"/",bucket,NULL);

	if(params && params[0] != 0) {
		ne_buffer_zappend(request_str,"?");
		ne_buffer_zappend(request_str,params);
	}

	req = ne_request_create(s3->session,method,request_str->data);

	// Add date header
	ne_add_request_header(req,"Date",date->data);

	// Add content-type header
	if(content_type) ne_add_request_header(req,"Content-Type",content_type);
	else content_type = "";

	// construct signing string
	p = strrchr(request_str->data,'?');
	if(p) {
		*p = 0;
		ne_buffer_altered(request_str);
	}
	ne_buffer_concat(signing_string,method,"\n\n",content_type,"\n",date->data,"\n",request_str->data,NULL);
	// sign the string
	sig = s3_sign_string(s3,signing_string->data);

	// construct signed header
	ne_print_request_header(req,"Authorization","AWS %s:%s",s3->access_id,sig);

	ne_buffer_destroy(date);
	ne_buffer_destroy(signing_string);
	ne_buffer_destroy(request_str);
	free(sig);

	return req;
}

int s3_create_bucket(S3 *s3,const char *bucket)
{
	ne_request *req;
	int err, retry;

	if(!s3) return -1;
	if(!bucket) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"PUT",bucket,NULL,NULL,NULL);

	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 200) {
				s3_handle_error_response(s3,req);
				err = -EACCES;
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

int s3_delete_bucket(S3 *s3,const char *bucket)
{
	ne_request *req;
	int err, retry;

	if(!s3) return -1;
	if(!bucket) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"DELETE",bucket,NULL,NULL,NULL);

	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 204) {
				s3_handle_error_response(s3,req);
				err = -EACCES;
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}


enum S3XmlStates
{
	XML_STATE_NONE,
	XML_STATE_LIST_BUCKET_RESULT,
	XML_STATE_CONTENTS,
	XML_STATE_KEY,
	XML_STATE_ETAG,
	XML_STATE_LAST_MODIFIED,
	XML_STATE_SIZE,
	XML_STATE_STORAGE_CLASS,
	XML_STATE_OWNER,
	XML_STATE_ID,
	XML_STATE_DISPLAY_NAME,
};

int s3_xml_key_info_startelm(void *userdata, int parent,
							const char *nspace, const char *name,
							const char **atts) {
	if(strcmp(name,"ListBucketResult") == 0) return XML_STATE_LIST_BUCKET_RESULT;
	if(parent == XML_STATE_LIST_BUCKET_RESULT && strcmp(name,"Contents") == 0) {
		S3KeyInfo *ki = userdata;
		ne_buffer_clear(ki->nb_name);
		ne_buffer_clear(ki->nb_etag);
		ne_buffer_clear(ki->nb_storage_class);
		ne_buffer_clear(ki->nb_owner_id);
		ne_buffer_clear(ki->nb_owner_display_name);
		return XML_STATE_CONTENTS;
	}
	if(parent == XML_STATE_CONTENTS) {
		if(strcasecmp(name,"Key") == 0) return XML_STATE_KEY;
		if(strcasecmp(name,"LastModified") == 0) return XML_STATE_LAST_MODIFIED;
		if(strcasecmp(name,"ETag") == 0) return XML_STATE_ETAG;
		if(strcasecmp(name,"Size") == 0) return XML_STATE_SIZE;
		if(strcasecmp(name,"StorageClass") == 0) return XML_STATE_STORAGE_CLASS;
		if(strcasecmp(name,"Owner") == 0) return XML_STATE_OWNER;
	}
	if(parent == XML_STATE_OWNER) {
		if(strcasecmp(name,"ID") == 0) return XML_STATE_ID;
		if(strcasecmp(name,"DisplayName") == 0) return XML_STATE_DISPLAY_NAME;
	}

	return parent;
}

int s3_xml_key_info_cdata(void *userdata, int state,
							const char *cdata, size_t len) {
	S3KeyInfo *ki = userdata;
	switch(state) {
		case XML_STATE_KEY:
			ne_buffer_append(ki->nb_name,cdata,len);
			break;
		case XML_STATE_ETAG:
			ne_buffer_append(ki->nb_etag,cdata,len);
			break;
		case XML_STATE_SIZE:
			ki->size = strtol(cdata,NULL,10);
			break;
		case XML_STATE_STORAGE_CLASS:
			ne_buffer_append(ki->nb_storage_class,cdata,len);
			break;
		case XML_STATE_ID:
			ne_buffer_append(ki->nb_owner_id,cdata,len);
			break;
		case XML_STATE_DISPLAY_NAME:
			ne_buffer_append(ki->nb_owner_display_name,cdata,len);
			break;
	}
	return 0;
}

int s3_xml_key_info_endelm(void *userdata, int state,
							const char *nspace, const char *name) {
	if(strcmp(name,"Contents") == 0) {
		S3KeyInfo *ki = userdata;
		ki->name = ki->nb_name->data;
		ki->etag = ki->nb_etag->data;
		ki->storage_class = ki->nb_storage_class->data;
		ki->owner_id = ki->nb_owner_id->data;
		ki->owner_display_name = ki->nb_owner_display_name->data;
		if(ki->key_info_cb) ki->key_info_cb->callback(ki->key_info_cb->userdata,ki);
	}
	return 0;
}

int s3_get_bucket(S3 *s3,const char *bucket,
	const char *prefix,const char *marker,int max_keys,const char *delimiter,
	const S3KeyInfoCallback *key_info_cb)
{
	ne_request *req;
	int err, retry;
	ne_buffer *params;

	if(!s3) return -1;
	if(!bucket) return -1;

	params = ne_buffer_create();
	if(prefix) ne_buffer_concat(params,"prefix=",prefix,"/&",NULL);
	if(marker) ne_buffer_concat(params,"marker=",marker,"&",NULL);
	if(max_keys >= 0) {
		char mk[16];
		snprintf(mk,16,"%d",max_keys);
		mk[15] = 0;
		ne_buffer_concat(params,"max_keys=",max_keys,"&",NULL);
	}
	if(delimiter) ne_buffer_concat(params,"delimiter=",delimiter,"&",NULL);

	s3_begin_session(s3);

	req = s3_new_request(s3,"GET",bucket,NULL,params->data,NULL);

	ne_buffer_destroy(params);

	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 200) {
				s3_handle_error_response(s3,req);
				err = -EACCES;
			} else {
				s3->key_info.key_info_cb = key_info_cb;
				s3_parse_xml_response(s3,
					req,
					s3_xml_key_info_startelm,
					s3_xml_key_info_cdata,
					s3_xml_key_info_endelm,
					&s3->key_info
				);
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

int s3_put_object(S3 *s3,const char *bucket,const char *key,const char *content_type,int content_length,const S3ReadCallback *rcb)
{
	ne_request *req;
	int err, retry;

	if(!s3) return -1;
	if(!bucket) return -1;
	if(!rcb) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"PUT",bucket,key,NULL,content_type);

	ne_print_request_header(req,"Content-Length","%d",content_length);

#ifdef NE_LFS
	ne_set_request_body_provider64(req,content_length,rcb->callback,rcb->userdata);
#else
	ne_set_request_body_provider(req,content_length,rcb->callback,rcb->userdata);
#endif

	//ne_set_request_body_buffer(req,"hello",5);
	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 200) {
				s3_handle_error_response(s3,req);
				err = -EACCES;
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

int s3_get_object(S3 *s3,const char *bucket,const char *key,const S3WriteCallback *wcb)
{
	ne_request *req;
	int err, retry;

	if(!s3) return -1;
	if(!bucket) return -1;
	if(!wcb) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"GET",bucket,key,NULL,NULL);
	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 200) {
				s3_handle_error_response(s3,req);
				if(ne_get_status(req)->code == 404) err = -ENOENT;
				else err = -EACCES;
			} else {
				char buffer[4096];
				size_t bytes_read;

				while((bytes_read = ne_read_response_block(req,buffer,4096)) > 0) {
					wcb->callback(wcb->userdata,buffer,bytes_read);
				}
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

int s3_head_object(S3 *s3,const char *bucket,const char *key,S3ObjectInfo *oi)
{
	ne_request *req;
	int err;

	if(!s3) return -1;
	if(!bucket) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"HEAD",bucket,key,NULL,NULL);

	// send to server
	err = ne_request_dispatch(req);
	if(err != NE_OK) err = -EIO;

	if(ne_get_status(req)->code != 200) {
		s3_handle_error_response(s3,req);
		if(ne_get_status(req)->code == 404) err = -ENOENT;
		else err = -EACCES;
	} else if(oi) {
		const char *str;
		str = ne_get_response_header(req,"Content-Length");
		if(str) oi->content_length = strtol(str,NULL,10);
		str = ne_get_response_header(req,"Content-Type");
		if(str) {
			strncpy(oi->content_type,str,31);
			oi->content_type[31] = 0;
		}
		str = ne_get_response_header(req,"ETag");
		if(str) {
			strncpy(oi->etag,str,79);
			oi->etag[79] = 0;
		}
	}

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

int s3_delete_object(S3 *s3,const char *bucket,const char *key)
{
	ne_request *req;
	int err, retry;

	if(!s3) return -1;
	if(!bucket) return -1;

	s3_begin_session(s3);

	req = s3_new_request(s3,"DELETE",bucket,key,NULL,NULL);

	// send to server
	do {
		err = ne_begin_request(req);
		if(err != NE_OK) err = -EIO;
		else {
			if(ne_get_status(req)->code != 204) {
				s3_handle_error_response(s3,req);
				err = -EACCES;
			}
			retry = ne_end_request(req);
		}
	} while(retry == NE_RETRY);

	ne_request_destroy(req);
	s3_end_session(s3);

	return err;
}

static ssize_t file_read_cb(FILE *fp,char *buffer,size_t len)
{
	size_t bytes_read;

	if(!fp) return -1;

	if(len == 0) {
		fseek(fp,0L,0);
		return 0;
	}
	clearerr(fp);
	bytes_read = fread(buffer,1,len,fp);
	if(bytes_read == 0) {
		if(ferror(fp)) return -1;
		if(feof(fp)) return 0;
		return 0;
	}
	return bytes_read;
}

static ssize_t file_write_cb(FILE *fp,char *buffer,size_t len)
{
	size_t bytes_written;

	if(!fp) return -1;

	clearerr(fp);
	bytes_written = fwrite(buffer,1,len,fp);
	if(bytes_written == 0) {
		if(ferror(fp)) return -1;
		if(feof(fp)) return 0;
		return 0;
	}
	return bytes_written;
}

const S3ReadCallback *s3_file_rcb(FILE *fp)
{
	static S3ReadCallback rcb;

	rcb.callback = (ssize_t (*)(void *,char *,size_t))file_read_cb;
	rcb.userdata = (void *)fp;

	return &rcb;
}

const S3WriteCallback *s3_file_wcb(FILE *fp)
{
	static S3WriteCallback wc;

	wc.callback = (ssize_t (*)(void *,char *,size_t))file_write_cb;
	wc.userdata = (void *)fp;

	return &wc;
}

typedef struct _MemInfo {
	void *data;
	unsigned int ptr;
	unsigned int len;
} MemInfo;

static ssize_t mem_read_cb(MemInfo *mi,char *buffer,size_t len)
{
	size_t bytes_read;

	if(len == 0) {
		mi->ptr = 0;
		return 0;
	}

	if(mi->ptr == mi->len) return 0;

	if((mi->len - mi->ptr) < len) {
		bytes_read = mi->len - mi->ptr;
		memcpy(buffer,mi->data + mi->ptr,bytes_read);
		mi->ptr = mi->len;
	} else {
		bytes_read = len;
		memcpy(buffer,mi->data + mi->ptr,len);
		mi->ptr += len;
	}

	return bytes_read;
}

static ssize_t mem_write_cb(MemInfo *mi,char *buffer,size_t len)
{
	size_t bytes_written;

	if(mi->ptr == mi->len) return 0;

	if(len > (mi->len - mi->ptr)) {
		bytes_written = mi->len - mi->ptr;
		memcpy(mi->data + mi->ptr,buffer,bytes_written);
		mi->ptr = mi->len;
	} else {
		bytes_written = len;
		memcpy(mi->data + mi->ptr,buffer,len);
		mi->ptr += len;
	}

	return bytes_written;
}

const S3ReadCallback *s3_mem_rcb(void *mem,unsigned int len)
{
	static S3ReadCallback rcb;
	static MemInfo info;

	info.data = mem;
	info.len = len;
	info.ptr = 0;
	rcb.callback = (ssize_t (*)(void *,char *,size_t))mem_read_cb;
	rcb.userdata = (void *)&info;

	return &rcb;
}

const S3WriteCallback *s3_mem_wcb(void *mem,unsigned int len)
{
	static S3WriteCallback wc;
	static MemInfo info;

	info.data = mem;
	info.len = len;
	info.ptr = 0;
	wc.callback = (ssize_t (*)(void *,char *,size_t))mem_write_cb;
	wc.userdata = (void *)&info;

	return &wc;
}
