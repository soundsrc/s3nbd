/***************************************************************************
 *   Copyright (C) 2007 by Sound   *
 *   sound@sagaforce.com   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <inttypes.h>

#include <linux/types.h>
#include <linux/nbd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "libs3.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#define ntohll(x)
#define htonll(x)
#else

uint64_t bswap64(uint64_t n) {
	uint8_t *c = (uint8_t *)&n;

	c[0] ^= c[7];
	c[1] ^= c[6];
	c[2] ^= c[5];
	c[3] ^= c[4];
	c[7] ^= c[0];
	c[6] ^= c[1];
	c[5] ^= c[2];
	c[4] ^= c[3];
	c[0] ^= c[7];
	c[1] ^= c[6];
	c[2] ^= c[5];
	c[3] ^= c[4];

	return *(uint64_t *)c;
}

#define ntohll(x) bswap64(x)
#define htonll(x) bswap64(x)

#endif

static char aws_access_id[256];
static char aws_secret_key[256];
static char aws_bucket[256];

inline static int read_sock(int sock,void *buffer,size_t len)
{
	size_t bytes_read;
	while(len > 0) {
		bytes_read = read(sock,buffer,len);
		if(errno == EAGAIN) {
			continue;
		}
		len -= bytes_read;
		buffer += bytes_read;
	}
	return 0;
}

inline static int write_sock(int sock,void *buffer,size_t len)
{
	size_t bytes_written;
	while(len > 0) {
		bytes_written = write(sock,buffer,len);
        if(errno == EAGAIN) {
			continue;
		}
		len -= bytes_written;
		buffer += bytes_written;
	}
	return 0;
}

#define BLOCK_SIZE 4096

static int s3fs_read_block(S3 *s3,const char *bucket,char *buffer,off_t blockno,size_t size,off_t offset)
{
	int res;
	unsigned char block[BLOCK_SIZE];
	char key[32];

	if(offset + size > BLOCK_SIZE) return -1;

	snprintf(key,32,"nbd/%.16llx",blockno); key[31] = 0;
#if __DEBUG__
	printf("  s3_get() path=/%s/%s, block=%lld, size=%d, offset=%lld\n",bucket,key,blockno,BLOCK_SIZE,offset);
#endif
	res = s3_get_object(s3,bucket,key,s3_mem_wcb(block,BLOCK_SIZE));
	if(res == -ENOENT) {
#if __DEBUG__
	printf("  s3_is_sparse() path=/%s/%s\n",bucket,key);
#endif
		memset(block,0,BLOCK_SIZE);
	} else if(res != 0) {
		fprintf(stderr,"%s\n",s3->error);
		return -1;
	}
	// copy relevant portion
	memcpy(buffer,block + offset,size);

	return 0;
}

static int s3fs_read(S3 *s3,const char *bucket,char *buffer,size_t size,off_t offset)
{
	uint64_t i, start_block, end_block;
	unsigned int bytes_to_read, remaining;
	int res;

	// compute start and end block
	start_block = offset / BLOCK_SIZE;
	end_block = (offset + size - 1) / BLOCK_SIZE;

#if __DEBUG__
	printf("read() size=%d, offset=%lld\n",size,offset);
#endif
	remaining = size;
	if(start_block == end_block) {
		res = s3fs_read_block(s3,bucket,buffer,start_block,size,offset & (BLOCK_SIZE - 1));
	} else {
		// copy start block portion
		bytes_to_read = BLOCK_SIZE - (offset & (BLOCK_SIZE - 1));
		res = s3fs_read_block(s3,bucket,buffer,start_block,bytes_to_read,offset & (BLOCK_SIZE - 1));
		buffer += bytes_to_read;
		remaining -= bytes_to_read;

		// copy each block in between
		for(i = start_block + 1; i < end_block; i++) {
			s3fs_read_block(s3,bucket,buffer,i,BLOCK_SIZE,0);
			buffer += BLOCK_SIZE;
			remaining -= BLOCK_SIZE;
		}

		// copy end block portion
		res = s3fs_read_block(s3,bucket,buffer,end_block,remaining,0);
	}

	return res;
}

// size must be multiple of 4
static int is_zero_block(unsigned char *buffer,size_t size)
{
	uint32_t *d;

	d = (uint32_t *)buffer;
	size &= ~3;
	while(size > 3) {
		if(*d++) return 0;
		size -= 4;
	}
	return 1;
}

static int s3fs_write_block(S3 *s3,const char *bucket,char *buffer,off_t blockno,size_t size,off_t offset)
{
	int res;
	unsigned char block[BLOCK_SIZE];
	char key[32];

	if(offset + size > BLOCK_SIZE) return -1;

	snprintf(key,32,"nbd/%.16llx",blockno); key[31] = 0;
	if(size != BLOCK_SIZE) {
		res = s3_get_object(s3,bucket,key,s3_mem_wcb(block,BLOCK_SIZE));
		if(res == -ENOENT) {
			memset(block,0,BLOCK_SIZE);
#if __DEBUG__
	printf("  s3_get() path=/%s/%s, size=%d\n",bucket,key,BLOCK_SIZE);
#endif
		} else if(res != 0) return -1;
#if __DEBUG__
	printf("  s3_get() path=/%s/%s, size=%d\n",bucket,key,BLOCK_SIZE);
#endif
	} else memset(block,0,BLOCK_SIZE);

	memcpy(block + offset,buffer,size);
	if(is_zero_block(block,BLOCK_SIZE)) {
		s3_delete_object(s3,bucket,key);
#if __DEBUG__
	printf("  s3_delete() path=/%s/%s\n",bucket,key);
#endif
	} else {
		s3_put_object(s3,bucket,key,"binary/octet-stream",BLOCK_SIZE,s3_mem_rcb(block,BLOCK_SIZE));
#if __DEBUG__
	printf("  s3put() path=/%s/%s, block=%lld, size=%d, offset=%lld\n",bucket,key,blockno,BLOCK_SIZE,offset);
#endif
	}

	return 0;
}

static int s3fs_write(S3 *s3,const char *bucket,char *buffer,size_t size,off_t offset)
{
	uint64_t i, start_block, end_block;
	int res = 0;
	unsigned int bytes_to_write, remaining;

	start_block = offset / BLOCK_SIZE;
	end_block = (offset + size - 1) / BLOCK_SIZE;

#if __DEBUG__
	printf("write() size=%d, offset=%lld\n",size,offset);
#endif
	remaining = size;
	if(start_block == end_block) {
		res = s3fs_write_block(s3,bucket,buffer,start_block,size,offset & (BLOCK_SIZE - 1));
	} else {
		bytes_to_write = BLOCK_SIZE - (offset & (BLOCK_SIZE - 1));
		res = s3fs_write_block(s3,bucket,buffer,start_block,bytes_to_write,offset & (BLOCK_SIZE - 1));
        buffer += bytes_to_write;
		remaining -= bytes_to_write;

		for(i = start_block + 1; i < end_block; i++) {
			res = s3fs_write_block(s3,bucket,buffer,i,BLOCK_SIZE,0);
			buffer += BLOCK_SIZE;
			remaining -= BLOCK_SIZE;
		}

		res = s3fs_write_block(s3,bucket,buffer,end_block,remaining,0);
	}

	return res;
}

int s3fs_server(int sock)
{
	// negotiation??
	char zeros[128];
	uint64_t magic, size;
	char block[32768];
	struct nbd_request request;
	struct nbd_reply reply;
	S3 *s3;

	s3 = new_S3(aws_access_id,aws_secret_key);

	if(write_sock(sock,"NBDMAGIC",8) < 0) {
		fprintf(stderr,"Negotiation failed.\n");
		return -1;
	}

	magic = htonll(0x00420281861253LL);
	if(write_sock(sock,&magic,sizeof(magic)) < 0) {
		fprintf(stderr,"Negotiation failed.\n");
		return -1;
	}

	size = htonll(0x1FFFFFFFFFFLL);
	if(write_sock(sock,&size,8) < 0) {
		fprintf(stderr,"Negotiation failed.\n");
		return -1;
	}

	memset(zeros,10,128);
	if(write_sock(sock,zeros,128) < 0) {
		fprintf(stderr,"Negotiation failed.\n");
		return -1;
	}

#if __DEBUG__
	printf("Server up.\n");
#endif

	// enter the main loop
	for(;;) {
		if(read_sock(sock,&request,sizeof(struct nbd_request)) < 0) {
			fprintf(stderr,"Read failure.\n");
			return -1;
		}

		if(ntohl(request.magic) != NBD_REQUEST_MAGIC) {
			fprintf(stderr,"Protocol error.\n");
			return -1;
		}

		switch(ntohl(request.type)) {
			case NBD_CMD_READ:
				{
					uint32_t len;
					uint64_t from;

					reply.magic = htonl(NBD_REPLY_MAGIC);
					reply.error = htonl(0);
					memcpy(reply.handle,request.handle,8);
					write_sock(sock,&reply,sizeof(struct nbd_reply));

					len = ntohl(request.len);
					from = ntohll(request.from);
					while(len > 32768) {
						s3fs_read(s3,aws_bucket,block,32768,from);
						write_sock(sock,block,32768);
						len -= 32768;
						from += 32768;
					}
					s3fs_read(s3,aws_bucket,block,len,from);
					write_sock(sock,block,len);
				}
				break;
			case NBD_CMD_WRITE:
				{
					uint32_t len;
					uint64_t from;

					len = ntohl(request.len);
					from = ntohll(request.from);
					while(len > 32768) {
						read_sock(sock,block,32768);
						s3fs_write(s3,aws_bucket,block,32768,from);
						len -= 32768;
						from += 32768;
					}
					read_sock(sock,block,len);
					s3fs_write(s3,aws_bucket,block,len,from);

					reply.magic = htonl(NBD_REPLY_MAGIC);
					reply.error = htonl(0);
					memcpy(reply.handle,request.handle,8);
					write_sock(sock,&reply,sizeof(struct nbd_reply));
				}
				break;
			case NBD_CMD_DISC:
				goto disc;
			default:
				fprintf(stderr,"Protocol error.\n");
				return -1;
		}
	}

disc:
#if __DEBUG__
	printf("Client disconnected.\n");
#endif
	free_S3(s3);
	memset(aws_access_id,0,256);
	memset(aws_secret_key,0,256);

	return 0;
}


int main(int argc, char *argv[])
{
	int sockfd, res, yes = 1, c, len;
	int port = 5353;
	struct sockaddr_in server_addr;
	struct option long_options[] =
	{
		{ "port", 1, 0, 'P' },
		{ "id", 1, 0, 'i' },
		{ "secret", 1, 0, 's' },
		{ "bucket", 1, 0, 'b' },
		{ 0, 0, 0, 0 }
	};
	int option_index = 0;
	S3 *s3;

	aws_access_id[0] = 0;
	aws_secret_key[0] = 0;
	aws_bucket[0] = 0;

	while((c = getopt_long(argc,argv,"p:i:s:b:",long_options,&option_index)) != -1) {
		switch(c) {
			case 'p':
				port = strtol(optarg,NULL,0);
				break;
			case 'i':
				strncpy(aws_access_id,optarg,256);
				aws_access_id[255] = 0;
				break;
			case 's':
				strncpy(aws_secret_key,optarg,256);
				aws_secret_key[255] = 0;
				break;
			case 'b':
				strncpy(aws_bucket,optarg,256);
				aws_bucket[255] = 0;
				break;
			default:
				fprintf(stderr,"Usage: s3fs-nbd [options..]\n");
				fprintf(stderr,"Options:\n");
				fprintf(stderr,"  -p PORT, --port=PORT       Listen on port (default: 5353).\n");
				fprintf(stderr,"  -i ID, --id=ID             Specify AWS ID.\n");
				fprintf(stderr,"  -s SECRET, --secret=SECRET AWS secret key.\n");
				fprintf(stderr,"  -b BUCKET, --bucket=BUCKET AWS bucket to use.\n");
				fprintf(stderr,"\n");
				exit(1);
		}
	}

	// prompt for access id
	if(aws_access_id[0] == 0) {
		printf("AWS ID: ");
		fflush(stdout);
		fgets(aws_access_id,256,stdin);
		aws_access_id[255] = 0;
		len = strlen(aws_access_id);
		while(len && aws_access_id[--len] == '\n')
			aws_access_id[len] = 0;
	}

	if(aws_secret_key[0] == 0) {
		printf("AWS Secret Key: ");
		fflush(stdout);
		fgets(aws_secret_key,256,stdin);
		aws_secret_key[255] = 0;
		len = strlen(aws_secret_key);
		while(len && aws_secret_key[--len] == '\n')
			aws_secret_key[len] = 0;
	}

	if(aws_bucket[0] == 0) {
		printf("AWS Bucket: ");
		fflush(stdout);
		fgets(aws_bucket,256,stdin);
		aws_bucket[255] = 0;
		len = strlen(aws_bucket);
		while(len && aws_bucket[--len] == '\n')
			aws_bucket[len] = 0;
	}

	// test credentials
	s3 = new_S3(aws_access_id,aws_secret_key);
	res = s3_head_object(s3,aws_bucket,"test",NULL);
	if(res != 0 && res != -ENOENT) {
		fprintf(stderr,"It seems that we cannot connect to amazon S3. Please check access id, secret key and bucket.\n");
		free_S3(s3);
		return -1;
	}
	free_S3(s3);

	// make socket
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd < 0) {
		fprintf(stderr,"Failed to create socket.\n");
		return -1;
	}

	memset(&server_addr,0,sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(5353);

	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));

	res = bind(sockfd,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
	if(res < 0) {
		fprintf(stderr,"Failed to bind socket.\n");
		return -1;
	}

	res = listen(sockfd,1);
	if(res < 0) {
		fprintf(stderr,"Failed to listen on socket.\n");
		return -1;
	}

	for(;;) {
		int sock;
		struct sockaddr_in client_addr;
		socklen_t sin_size;

		sock = accept(sockfd,(struct sockaddr *)&client_addr,&sin_size);
		if(sock < 0) {
			fprintf(stderr,"Failed to accept connection.\n");
			continue;
		}

		s3fs_server(sock);
	}
}
