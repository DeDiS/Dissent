/* 
 * COPYRIGHT AND DISCLAIMER
 * 
 * Copyright (C) 1996-1997 by the Regents of the University of California.
 *
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY DERIVATIVES THEREOF,
 * EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. THIS SOFTWARE IS
 * PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * For inquiries email Steve Gribble <gribble@cs.berkeley.edu>.
 */

/*
 *     Author: Steve Gribble - gribble@cs.berkeley.edu
 *       Date: Nov. 19th, 1996
 *       File: anon_clients.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "logparse.h"
#include "md5.h"

#define CLIENT_BLOCK_SIZE 5000

int sanitycheck(lf_entry *entry);
void anon_switcheroo_url(unsigned char *orig_url, UINT16 orig_urllen,
			 unsigned char **new_url, UINT16 *new_urllen);

int main(int argc, char **argv)
{
  lf_entry *lfn_array;
  int      ret, i, done=0, j;
  MD5_CTX  tCrypt;

  lfn_array = (lf_entry *) malloc((CLIENT_BLOCK_SIZE+1)*sizeof(lf_entry));
  if (lfn_array == NULL) {
    fprintf(stderr, "Out of memory allocating lfn_array.\n");
    exit(1);
  }
  
  if (argc != 1) {
    fprintf(stderr, "Usage: anon_clients < infile(s)\n");
    exit(1);
  }

  while(!done) {
    for (i=0; i<CLIENT_BLOCK_SIZE; i++) {
      if ((ret = lf_get_next_entry(0, lfn_array+(unsigned long)i, 0)) != 0) {
	if (ret == 1)  /* EOF */
          break;
	fprintf(stderr, "Failed to get next entry.\n");
	exit(1);
      }
    }
    fprintf(stderr, "Got %d entries in block, processing.\n", i);
    if (i != CLIENT_BLOCK_SIZE)
      done = 1;

    /* OK - we've sucked in a block of i lfntrees.  Let's dump em out
       to the right client files. */
    for (j=0; j<i; j++) {
      lf_entry *t = lfn_array + (unsigned long) j;

      if (t->url == NULL) {
	/* just skip to next */
      } else if (!sanitycheck(t)) {
	fprintf(stderr, "!!!url failed sanitycheck!!!\n");
	free(t->url);
	t->url = NULL;
      } else {
	char             cbuf[125];
	unsigned char   *new_url = NULL;
	UINT16  new_urllen = 0;

	MD5Init(&tCrypt);
	MD5Update(&tCrypt, "secret_sauce", strlen("secret_sauce"));
                /* and no, that is not the key that I used... */
	sprintf(cbuf, "%lu", t->cip);
	MD5Update(&tCrypt, cbuf, strlen(cbuf));
	MD5Final(&tCrypt);
	memcpy(&(t->cip), &(tCrypt.digest[0]), sizeof(t->cip));

	MD5Init(&tCrypt);
	MD5Update(&tCrypt, "secret_sauce", strlen("secret_sauce"));
	sprintf(cbuf, "%lu", t->sip);
	MD5Update(&tCrypt, cbuf, strlen(cbuf));
	MD5Final(&tCrypt);
	memcpy(&(t->sip), &(tCrypt.digest[0]), sizeof(t->sip));

	anon_switcheroo_url(t->url, t->urllen, &new_url, &new_urllen);
	if (new_urllen != 0) {
	  free(t->url);
	  t->url = new_url;
	  t->urllen = new_urllen;
	}
	lf_write(stdout, t);
	free(t->url);
	t->url = NULL;
	t->urllen = 0;
      }
    }
  }
  exit(0);
}

#define OP_GET 1
#define OP_POST 2
#define OP_HEAD 3
#define OP_OTHER 4
#define OP_PUT 5
#define VER_HTTP_09 0
#define VER_HTTP_10 1
#define VER_HTTP_11 2

#define GOTNONE 0
#define GOTDOT  1
#define GOTDONE 3

void anon_switcheroo_url(unsigned char *orig_url, UINT16 orig_urllen,
			 unsigned char **new_url, UINT16 *new_urllen)
{
  int op = OP_OTHER, i;
  int http_vers = VER_HTTP_09;
  int offset, url_start, url_end, maxscan;
  int state = GOTNONE, ques = 0, cgi = 0, start_dot = -1, end_dot = -1;
  unsigned char bup;
  MD5_CTX tCrypt;

  *new_url = NULL;
  *new_urllen = 0;

/*  fprintf(stderr, "url (%d): %s\n", orig_urllen, orig_url); */
  
  if (orig_urllen == 0)
    return;

  /* What kind of request is this? */
  if (strncmp((char *) orig_url, "GET ", 4) == 0) {
    op = OP_GET;
  } else if (strncmp((char *) orig_url, "POST ", 5) == 0) {
    op = OP_POST;
  } else if (strncmp((char *) orig_url, "HEAD ", 5) == 0) {
    op = OP_HEAD;
  } else if (strncmp((char *) orig_url, "PUT ", 4) == 0) {
    op = OP_PUT;
  }
  
  /* What does the request end in? (i.e. HTTP/1.0, etc) */
  if (orig_urllen > 10) {
    offset = orig_urllen - 8;
    if (strcmp((char *) (orig_url + offset), "HTTP/1.0") == 0)
      http_vers = VER_HTTP_10;
    else if (strcmp((char *) (orig_url + offset), "HTTP/1.1") == 0)
      http_vers = VER_HTTP_11;
  } else
    offset = 0;

  /* Find boundaries of URL */
  if (orig_urllen < 8)
    maxscan = 8;
  else
    maxscan = orig_urllen;
  url_start = url_end = -1;
  for (i=0; i<maxscan; i++) {
    if ((orig_url[i] == ' ') || (orig_url[i] == '\t')) {
      while ((orig_url[i] == ' ') || (orig_url[i] == '\t'))
	i++;
      url_start = i;
      break;
    }
  }
  if (url_start == -1)
    return;
  for (i=offset; i>url_start; i--) {
    if ((orig_url[i] == ' ') || (orig_url[i] == '\t')) {
      while ((orig_url[i] == ' ') || (orig_url[i] == '\t'))
	i--;
      i++;
      url_end = i;
      break;
    }
  }
  
  bup = orig_url[url_end];
  orig_url[url_end] = '\0';
/*   fprintf(stderr, "orig url(%d) is: %s\n!!!!\n", url_end-url_start+1, (char *) 
	  (orig_url+url_start)); */

  /* scan through url and glean some information, like the URL suffix (if it exists)
     and if a question mark exists */
  for (i=url_start; i<url_end; i++) {
    if (state == GOTDONE)
      break;
    switch(state) {
    case GOTNONE:
      if (orig_url[i] == '.') {
	start_dot = i;
	state = GOTDOT;
	continue;
      } else if (orig_url[i] == '?') {
	ques = 1;
	state = GOTDONE;
	continue;
      } else if (orig_url[i] == ' ') {
	state = GOTDONE;
	continue;
      }
      break;
    case GOTDOT:
      if (orig_url[i] == '?') {
	ques = 1;
	end_dot = i;
	state = GOTDONE;
	continue;
      } else if (orig_url[i] == ' ') {
	end_dot = i;
	state = GOTDONE;
	continue;
      } else if (orig_url[i] == '.') {
	start_dot = i;
	continue;
      }
      break;
    }
  }
  if (start_dot != -1 && end_dot == -1)
    end_dot = url_end;
  if ((strstr((char *) &(orig_url[url_start]), "cgi") != 0) ||
      (strstr((char *) &(orig_url[url_start]), "CGI") != 0)) {
    cgi = 1;
  }
  orig_url[url_end] = bup;

  /* do MD5 on url */
  MD5Init(&tCrypt);
  MD5Update(&tCrypt, "secret_sauce", strlen("secret_sauce"));
  MD5Update(&tCrypt, orig_url, orig_urllen);
  MD5Final(&tCrypt);
  
  /* Construct the url to return */
  *new_urllen = 64;   /* enough for the huge MD5 numbers, the op, and the HTTP stuff */
  if (start_dot != -1)
    *new_urllen = *new_urllen + (end_dot - start_dot) + 1;
  *new_url = (unsigned char *) malloc(sizeof(char) * (*new_urllen));
  if (*new_url == NULL) {
    fprintf(stderr, "Out of memory\n");
    exit(1);
  }
  
  switch(op) {
  case OP_GET:
    sprintf((char *) *new_url, "GET ");
    break;
  case OP_POST:
    sprintf((char *) *new_url, "POST ");
    break;
  case OP_HEAD:
    sprintf((char *) *new_url, "HEAD ");
    break;
  case OP_PUT:
    sprintf((char *) *new_url, "PUT ");
    break;
  default:
    sprintf((char *) *new_url, "? ");
    break;
  }
  sprintf((char *) (*new_url + strlen((char *) *new_url)), "%lu",
	  *((unsigned long int *) &(tCrypt.digest[0])));
  sprintf((char *) (*new_url + strlen((char *) *new_url)), "%lu.",
	  *(((unsigned long int *) &(tCrypt.digest[0])) + 1));
  if (ques) {
    strcat((char *) *new_url, "q");
  }
  if (cgi) {
    strcat((char *) *new_url, "c");
  }
  if (start_dot != -1) {
    int buplen = strlen((char *) *new_url);
    memcpy((*new_url + buplen), orig_url+start_dot,
	   (end_dot-start_dot));
    *(*new_url + buplen + (end_dot-start_dot)) = '\0';
  }
  
  switch(http_vers) {
  case VER_HTTP_09:
    break;
  case VER_HTTP_10:
    strcat((char *) *new_url, " HTTP/1.0");
    break;
  case VER_HTTP_11:
    strcat((char *) *new_url, " HTTP/1.1");
    break;
  default:
    break;
  }

  *new_urllen = strlen((char *) *new_url);
  return;
}

int sanitycheck(lf_entry *entry)
{
  if ( (strcmp((char *) entry->url, "-") == 0) ||
       (strlen((char *) entry->url) < 4) ||
       (entry->sip == 0xFFFFFFFF) ||
       (entry->spt == 0xFFFF) ||
       !((strncmp((char *) entry->url, "GET ", 4) == 0) ||
	 (strncmp((char *) entry->url, "POST ", 5) == 0) ||
	 (strncmp((char *) entry->url, "HEAD ", 5) == 0) ||
	 (strncmp((char *) entry->url, "PUT ", 4) == 0)) )
    return 0;
  return 1;
}
