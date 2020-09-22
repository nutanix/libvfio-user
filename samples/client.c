/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include "../lib/muser.h"

static int
init_sock(const char *path)
{
    int ret, sock;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	/* TODO path should be defined elsewhere */
	ret = snprintf(addr.sun_path, sizeof addr.sun_path, path);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("failed to open socket");
		return sock;
	}

	if ((ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
		perror("failed to connect server");
        return ret;
	}
	return sock;
}

static int
set_version(int sock)
{
    int ret;
    char *server_data;
    size_t size;
    int server_mj, server_mn;
    struct vfio_user_header hdr;

    /* receive version from client */
    ret = recv(sock, &hdr, sizeof(hdr), 0);
    if (ret == -1) {
        perror("failed to receive version header");
        return -1;
    }

    if (ret < sizeof(hdr)) {
        fprintf(stderr, "short version header: %d\n", ret);
        return -1;
    }

    if (hdr.msg_size < sizeof(hdr)) {
        fprintf(stderr, "bad version data size: %d\n", hdr.msg_size);
        return -1;
    }
    size = hdr.msg_size - sizeof(hdr);
    server_data = malloc(size);
    if (server_data == NULL) {
        perror(NULL);
        return -1;
    }
    ret = recv(sock, server_data, size, 0);
    if (ret == -1) {
        perror("failed to receive server version");
        return -1;
    }

    if (ret < size) {
        fprintf(stderr, "short verson data read: %d", ret);
        return -1;
    }

    ret = sscanf(server_data, "{version: {\"major\": %d, \"minor\": %d}}",
                 &server_mj, &server_mn);
    if (ret != 2) {
        fprintf(stderr, "bad server version data %s\n", server_data);
        return -1;
    }
    if (server_mj != 0 || server_mn != 1) {
        fprintf(stderr, "bad server version %d.%d\n", server_mj, server_mn);
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
	int ret, sock;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/socket\n", argv[0]);
        return -1;
    }

    if ((sock = init_sock(argv[1])) == -1) {
        return sock;
    }

    if ((ret = set_version(sock)) == -1) {
        return ret;
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
