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
 *     Author: Steve Gribble
 *       Date: Nov. 23rd, 1996
 *       File: logparse.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#include "logparse.h"
#include "utils.h"

extern int errno;

/** 
 ** lf_get_next_entry will suck the next record out of the logfile, and
 ** return a lf_entry record witih the information stuffed into it.  Note
 ** that memory WILL be allocated for the url field;  the caller is
 ** responsible for freeing the memory when done.  The logfile should have
 ** everything stored in network order, if all is well.
 **
 ** This function returns 0 on success, 1 for EOF, and something else
 ** otherwise.  On failure,
 ** no memory will have been allocated.
 **/

int lf_get_next_entry(int logfile_fd, lf_entry *nextentry, int vers)
{
  unsigned char blockbuf[60], *tmp;
  int           uln, ret;

  if ((ret = correct_read(logfile_fd, (void *) blockbuf, (size_t) 60)) != 60) {
    if (ret == 0)
      return 1;
/*    fprintf(stderr, "read 60 failed...%d\n", ret); */
    return 2;
  }

  /* We got one! */
  nextentry->version = vers;
  memcpy( &(nextentry->crs),  blockbuf+0,  4);
  memcpy( &(nextentry->cru),  blockbuf+4,  4);
  memcpy( &(nextentry->srs),  blockbuf+8,  4);
  memcpy( &(nextentry->sru),  blockbuf+12, 4);
  memcpy( &(nextentry->sls),  blockbuf+16, 4);
  memcpy( &(nextentry->slu),  blockbuf+20, 4);
  memcpy( &(nextentry->cip),  blockbuf+24, 4);
  memcpy( &(nextentry->cpt),  blockbuf+28, 2);
  memcpy( &(nextentry->sip),  blockbuf+30, 4);
  memcpy( &(nextentry->spt),  blockbuf+34, 2);
  memcpy( &(nextentry->cprg), blockbuf+36, 1);
  memcpy( &(nextentry->sprg), blockbuf+37, 1);
  memcpy( &(nextentry->cims), blockbuf+38, 4);
  memcpy( &(nextentry->sexp), blockbuf+42, 4);
  memcpy( &(nextentry->slmd), blockbuf+46, 4);
  memcpy( &(nextentry->rhl),  blockbuf+50, 4);
  memcpy( &(nextentry->rdl),  blockbuf+54, 4);
  memcpy( &(nextentry->urllen), blockbuf+58, 2);

  /* Now let's read in that url */
  uln = ntohs(nextentry->urllen);
  nextentry->url = (unsigned char *) malloc(sizeof(char) * 
					    (int) (uln + 1));
  if (nextentry->url == NULL) {
    fprintf(stderr, "out of memory in lf_get_next_netry!\n");
    exit(1);
  }
  if ((ret = correct_read(logfile_fd, (void *) (nextentry->url), (size_t) uln))
      != uln ) {
    if (ret == 0) {
      free(nextentry->url);
      return 1;
    }
    fprintf(stderr, "read of %d failed %d\n", (size_t) uln, ret);
    perror("aargh.");
    free(nextentry->url);
    return 2;
  }
  tmp = nextentry->url;
  *(tmp + uln) = '\0';
  return 0;
}

/** 
 ** This function will convert all of the entries in the record into/from
 ** host order.  This function is its own inverse.  This function cannot
 ** fail.
 **/

void lf_convert_order(lf_entry *convertme)
{
  convertme->crs = ntohl(convertme->crs);
  convertme->cru = ntohl(convertme->cru);
  convertme->srs = ntohl(convertme->srs);
  convertme->sru = ntohl(convertme->sru);
  convertme->sls = ntohl(convertme->sls);
  convertme->slu = ntohl(convertme->slu);
  convertme->cip = ntohl(convertme->cip);
  convertme->cpt = ntohs(convertme->cpt);
  convertme->sip = ntohl(convertme->sip);
  convertme->spt = ntohs(convertme->spt);
  convertme->cims = ntohl(convertme->cims);
  convertme->sexp = ntohl(convertme->sexp);
  convertme->slmd = ntohl(convertme->slmd);
  convertme->rhl = ntohl(convertme->rhl);
  convertme->rdl = ntohl(convertme->rdl);
  convertme->urllen = ntohs(convertme->urllen);
}

/**
 ** This function will write the entry pointed to by writeme back
 ** out to the file outf, in the canonical logfile binary format.
 ** It returns 0 on success, something else on failure.
 **/
int  lf_write(FILE *outf, lf_entry *writeme)
{
  unsigned char blockbuf[60];
  int           uln, ret;

  memcpy( blockbuf+0, &(writeme->crs),   4);
  memcpy( blockbuf+4, &(writeme->cru),   4);
  memcpy( blockbuf+8, &(writeme->srs),   4);
  memcpy( blockbuf+12, &(writeme->sru),  4);
  memcpy( blockbuf+16, &(writeme->sls),  4);
  memcpy( blockbuf+20, &(writeme->slu),  4);
  memcpy( blockbuf+24, &(writeme->cip),  4);
  memcpy( blockbuf+28, &(writeme->cpt),  2);
  memcpy( blockbuf+30, &(writeme->sip),  4);
  memcpy( blockbuf+34, &(writeme->spt),  2);
  memcpy( blockbuf+36, &(writeme->cprg), 1);
  memcpy( blockbuf+37, &(writeme->sprg), 1);
  memcpy( blockbuf+38, &(writeme->cims), 4);
  memcpy( blockbuf+42, &(writeme->sexp), 4);
  memcpy( blockbuf+46, &(writeme->slmd), 4);
  memcpy( blockbuf+50, &(writeme->rhl),  4);
  memcpy( blockbuf+54, &(writeme->rdl),  4);
  memcpy( blockbuf+58, &(writeme->urllen), 2);

  ret = fwrite(&(blockbuf[0]), 60, 1, outf);
  if (ret != 1) {
    fprintf(stderr, "write 60 failed...%d\n", ret);
    perror("arrgh1");
    return 1;
  }

  /* Now let's write out that url */
  uln = ntohs(writeme->urllen);
  ret = fwrite(writeme->url, (size_t) uln, 1, outf);
  if (ret != 1) {
    fprintf(stderr, "write of %d failed %d\n", (size_t) uln, ret);
    perror("aargh.");
    return 2;
  }
  return 0;
}

/** 
 ** This function will dump a human-readable output version of the record
 ** to the passed-in file pointer.  Assume that the record is in NETWORK
 ** order. Nothing can possibly go wrong. :)
 **/
void lf_dump(FILE *dumpf, lf_entry *dumpme)
{
  char addr1buf[128], addr2buf[128];

  lf_convert_order(dumpme);
  lf_ntoa(dumpme->cip, addr1buf);
  lf_ntoa(dumpme->sip, addr2buf);
  fprintf(dumpf, "%lu:%lu %lu:%lu %lu:%lu %s:%hu %s:%hu %u %u ",
	  dumpme->crs, dumpme->cru, dumpme->srs, dumpme->sru,
	  dumpme->sls, dumpme->slu, addr1buf, dumpme->cpt,
	  addr2buf, dumpme->spt, dumpme->cprg, dumpme->sprg);
  fprintf(dumpf, "%lu %lu %lu %lu %lu %u %s\n",
	  dumpme->cims, dumpme->sexp, dumpme->slmd, dumpme->rhl,
	  dumpme->rdl, dumpme->urllen, dumpme->url);
  lf_convert_order(dumpme);
}

/** 
 ** lf_ntoa takes a network IP address (in host order) and converts it
 ** to an ascii representation. addrbuf had better be 16 bytes or
 ** more...
 **/
void lf_ntoa(unsigned long addr, char *addrbuf)
{
  sprintf(addrbuf, "%lu.%lu.%lu.%lu",
	  (addr >> 24),
	  (addr >> 16) % 256,
	  (addr >> 8) % 256,
	  (addr) % 256);
}
