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
 *       File: logparse.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "config.h"

#ifndef PB_LOGPARSE_H
#define PB_LOGPARSE_H

/* 
   EVERYTHING below is in NETWORK (yes, NETWORK) order.  If something
   is undefined in the traces, it is represented by FF...FF.  For
   example, an undefined client pragma is 0xFF, and an undefinfed
   server last response time is 0xFFFFFFFF.

   Version 1 trace records do not have pragmas, modified dates, or expiry
   dates.  Version 2 records have the PG_CLNT_NO_CACHE, PG_CLNT_KEEP_ALIVE
   pragmas, and no dates.  Version 3 records have all pragmas and dates.
*/

#define PB_CLNT_NO_CACHE       1
#define PB_CLNT_KEEP_ALIVE     2
#define PB_CLNT_CACHE_CNTRL    4
#define PB_CLNT_IF_MOD_SINCE   8
#define PB_CLNT_UNLESS         16

#define PB_SRVR_NO_CACHE       1
#define PB_SRVR_CACHE_CNTRL    2
#define PB_SRVR_EXPIRES        4
#define PB_SRVR_LAST_MODIFIED  8

typedef struct lf_entry_st {
  unsigned char  version; /* Trace record version */
  UINT32 crs;             /* client request seconds */
  UINT32 cru;             /* client request microseconds */
  UINT32 srs;             /* server first response byte seconds */
  UINT32 sru;             /* server first response byte microseconds */
  UINT32 sls;             /* server last response byte seconds */
  UINT32 slu;             /* server last response byte microseconds */
  UINT32 cip;             /* client IP address */
  UINT16 cpt;             /* client port */
  UINT32 sip;             /* server IP address */
  UINT16 spt;             /* server port */
  unsigned char  cprg;    /* client headers/pragmas */
  unsigned char  sprg;    /* server headers/pragmas */
  /* If a date is FFFFFFFF, it was missing/unreadable/unapplicable in trace */
  UINT32 cims;            /* client IF-MODIFIED-SINCE date, if applicable */
  UINT32 sexp;            /* server EXPIRES date, if applicable */
  UINT32 slmd;            /* server LAST-MODIFIED, if applicable */
  UINT32 rhl;             /* response HTTP header length */
  UINT32 rdl;             /* response data length, not including header */
  UINT16 urllen;          /* url length, not including NULL term */
  unsigned char *url;     /* request url, e.g. "GET / HTTP/1.0", + '\0' */
} lf_entry;

int  lf_get_next_entry(int logfile_fd, lf_entry *nextentry, int vers);
void lf_convert_order(lf_entry *convertme);
int  lf_write(FILE *outf, lf_entry *writeme);
void lf_dump(FILE *dumpf, lf_entry *dumpme);
void lf_ntoa(unsigned long addr, char *addrbuf);

#endif
