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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <assert.h>
#include <memory.h>
#include <string.h>

/*
 *  The following should be replaced
 */

#define SIZEOF_INT 4
#define SIZEOF_LONG 4

#if     SIZEOF_LONG == 4
typedef unsigned long UINT32;
#ifndef JPEGLIB_H
typedef signed long    INT32;
#endif
#elif   SIZEOF_INT == 4
typedef unsigned int  UINT32;
#ifndef JPEGLIB_H
typedef signed int     INT32;
#endif
#endif
#if     SIZEOF_INT == 2
#ifndef JPEGLIB_H
typedef unsigned int   UINT16;
#endif
#ifndef JPEGLIB_H
typedef signed int      INT16;
#endif
#else
#ifndef JPEGLIB_H
typedef unsigned short UINT16;
#endif
#ifndef JPEGLIB_H
typedef signed short    INT16;
#endif
#endif

#include <stdlib.h>
#include <malloc.h>

#endif /*ifndef _CONFIG_H */


