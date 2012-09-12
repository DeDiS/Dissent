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
 * utils.h --
 *
 * Various utility functions - sockets, linked list, hash tables.
 * $Id: utils.h,v 1.9 1997/02/27 00:58:31 gribble Exp $
 * 
 */

#ifndef ICP_UTILS
#define ICP_UTILS

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "config.h"

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TIMERS_H
#include <sys/timers.h>
#endif

/*
 ************* Dump out the hexification of the buffer ***********
 */
void dump_buf(FILE *std, char *buf, int retlen);

/*
 ************* Time munging utilities *****************
 */

typedef struct timeval  tv_time;
typedef struct timespec ts_time;

tv_time  tv_timeadd(tv_time t1, tv_time t2);
tv_time  tv_timesub(tv_time t1, tv_time t2);
tv_time  tv_timemul(tv_time t1, double mult);
int      tv_timecmp(tv_time t1, tv_time t2);

ts_time  ts_timeadd(ts_time t1, ts_time t2);
ts_time  ts_timesub(ts_time t1, ts_time t2);
ts_time  ts_timemul(ts_time t1, double mult);
int      ts_timecmp(ts_time t1, ts_time t2);

/*
 ************* Thread-safe strtok routines and state *************
 */

typedef struct ts_strtok_st {
  char *string_dupe;
  char *nxt_ptr;
  int   chars_remaining;
} ts_strtok_state;

/*
 * Thread-safe strtok routines!  Call ts_strtok_init with the string you
 * want tokenized.  It will return a pointer to some state.  Then you
 * call ts_strtok with the same semantics as strtok, more or less, except
 * you have to pass this state around.  When you're done, be sure to call
 * ts_strtok_finish to clean up the state.
 *
 * ts_strtok_init returns NULL if it runs out of memory, or if it is passed
 * a bogus string.  ts_strtok returns NULL in case of error,  ts_strtok_finish
 * returns 1 on success, 0 on error.x
 */

ts_strtok_state *ts_strtok_init(char *string);
char            *ts_strtok(char *matching, ts_strtok_state *state);
int              ts_strtok_finish(ts_strtok_state *state);

/************* A really dumb implementation of strnstr and strcasestr ***********/
char *dumb_strnstr(char *str, char *substr, int n);
const char *strcasestr(const char *string, const char *substr);

/*
 ***************** Socket convenience utilities ****************
 */

/*
 * correct_write will continue writing to a socket until it fails or
 * until all len bytes have been written.
 */

int correct_write(int s, char *data, int len);

/*
 * correct_read is like correct_write, but does a read.
 */

int correct_read(int s, char *data, int len);

/*
 * saccept takes an open socket, and blocks while performing an
 * "accept" system call.  "accept" waits for incoming connections from
 * client applications.  If the connection succeeds, the new socket
 * is returned, else an error is indicated through a negative return value.
 */

int saccept(int s);

/* 
 * nbaccept is similar to saccept, except that it is non-blocking.  If
 * a new connection is made, the new socket is returned in the rs
 * argument and 1 is returned.  If the accept call would have blocked,
 * 0 is returned.  -1 is returned on an error.
 */

int nbaccept(int s, int *rs);

/*
 * sconnect takes a string hostname or IP address, and a string port number
 * or service name as arguments.  It then creates a socket, and
 * performs the correct hostname/servicename to inet addr conversions.
 * It finally calls bind and connect as appropriate.  If all functions
 * perform successfully, a new file descriptor is returned, otherwise
 * -1 is returned.  sconnect is intended to be used by clients.
 */

int sconnect(char *hostname, char *servicename);

/*
 * This call attempts to set up a listening socket.  A listening socket
 * passively waits for connections (through the accept command).  The
 * function accepts a string port number or service name that clients
 * will use to contact this listening socket.  The socket, inet addr
 * conversion, bind, and listen functions are performed.  If all succeed,
 * the new listening file descriptor will be returned, else -1 will be
 * returned.
 */

int slisten(char *servicename);

/*
 * This function accepts a socket file descriptor, and returns the port
 * number that it corresponds to, or -1 in case of error.
 */

int sportnum(int s);

/*
 * This primitive function creates the sockaddr_in structure corresponding
 * to the hostname/IPaddress and servicename/portnumber pair passed in
 * as arguments.  In case of error, -1 is returned, else 0 is returned.
 */

int make_inetaddr(char *hostname, char *servicename, 
                  struct sockaddr_in *inaddr);

/*
 * This primitive function returns the protocol entry number corresponding
 * to the protocol string passed in, or -1 in case of error.
 */

int protonumber(char *protoname);

/* these return -1 for error, 0 for wouldblock, 1 for wouldsucceed */

/*
 * test_readable returns 1 if data is available to be read, 0 if no data
 * is available to be read and thus a read would block, or -1 in case of
 * an error.
 */

int test_readable(int s);

/*
 * test_writable returns 1 if a subsequent write-a-byte operation would
 * succeed, 0 if it would block, and -1 in case of error.
 */

int test_writable(int s);

/*
 ***************** Linked-list routines ****************
 */

/*
 * the "ll_node" structure contains a node of a linked list.  Note that
 * a NULL "ll" type implies an empty linked-list.
 */

typedef struct ll_st {
  void         *data;
  struct ll_st *next;
  struct ll_st *prev;
} ll_node, *ll;

/*
 * ll_add_to_end adds data to the end of a linked list.  A new node
 * is always created.  If the list previously didn't exist, then a
 * new list is created and the addToMe variable updated accordingly.
 * This function returns 1 for success.  If we run out of memory, die.
 */

int ll_add_to_end(ll *addToMe, void *data);

/*
 * ll_add_to_start is identical to ll_add_to_end, except the new data
 * is added to the start of the linked list.
 */

int ll_add_to_start(ll *addToMe, void *data);

/* 
 * ll_find traverses the linked list, looking for a node containing
 * data that matches the "data" argument, according to the "compare"
 * comparator function.  "compare" should return 0 if for equal, -1
 * for d1 less than d2, and +1 for d1 greater than d2.  ll_find
 * returns a pointer to the first found node, or NULL if such a node
 * doesn't exist.
 */

ll  ll_find(ll *findInMe, void *data, int (*compare)(void *d1, void *d2));

/*
 * ll_sorted_insert will perform a list element insertion, but will
 * do so in sorted (increasing) order.  This function returns 1 for
 * success, and dies on failure.
 */

int ll_sorted_insert(ll *insertme, void *data, 
		     int (*compare)(void *d1, void *d2));


/*
 * ll_del performs an ll_find operation on the "data" argument.  If
 * a node is found, it is removed from the linked list and the data field
 * of the node freed with the "nukeElement" function.  (If "nukeElement"
 * is NULL, the free is avoided.)  If the linked list becomes empty,
 * "*delFromMe" becomes NULL.  If multiple nodes match the "data" argument,
 * only the first is removed.  This function returns 1 if a node is found
 * and removed, or 0 otherwise.
 */

int ll_del(ll *delFromMe, void *data, int (*compare)(void *d1, void *d2),
           void (*nukeElement)(void *nukeMe));

/*
 * ll_delfirst deletes the first element from the list, if it exists.
 * If nukeElement is NULL, the element is not free'd.  This function
 * returns 1 on success, 0 otherwise.
 */

int ll_delfirst(ll *delFromMe, void (*nukeElement)(void *nukeMe));


/*
 * ll_destroy removes all nodes from a list, and calls "nukeElement" on
 * the data field of all nodes.  If "nukeElement" is NULL, no operation
 * is performed on the data field, but the destroy proceeds.  This
 * function always returns 1.
 */

int ll_destroy(ll *destroyMe, void (*nukeElement)(void *nukeMe));

/*
 * ll_build takes a string of the form [a, b, c, .. ] and returns a linked
 * list with elements from the string.  It malloc's space for the new
 * linked list element strings.  The function returns 1 on success, and
 * 0 in case of an error.
 */

int ll_build(ll *buildMe, char *buildFromMe);

/*
 ***************** Hash table routines ****************
 */

typedef ll       hash_el;
typedef struct hash_table_st {
    int num_elements;
    hash_el *slot_array;
} hash_table;
typedef int (*hash_function)(void *element, int num_slots);
typedef int (*sc_comparator)(void *element1, void *element2);
typedef void (*deletor)(void *element);

/*
 * chained_hash_create creates a new chained hash table, with room for
 * "num_slots" slots.  If the creation succeeds, the new table is passed back
 * in the rt variable and 0 is returned, else -1 is returned.
 */

int chained_hash_create(int num_slots, hash_table *rt);

/*
 * chained_hash_destroy destroys a previously created hash table.  It
 * first purges the chains of all non-empty slots in the table, and then
 * frees the table itself.  0 is always returned.
 */

int chained_hash_destroy(hash_table ht, deletor d);

/*
 * chained_hash_insert first uses the hash_function f to acquire the
 * hash slot for the element "element", and then inserts that element
 * into the slot's list.  0 is returned in case of success, and -1 in
 * case of failure.
 */

int chained_hash_insert(hash_table ht, void *element, hash_function f);

/*
 * chained_hash_search finds the stored element matching "element" in
 * table ht according to comparator function "c".  "c" must return 0
 * if two elements match, 1 if the first argument is greater, and -1 if
 * the first argument is less.  If an element is found, it is returned,
 * else NULL is returned.
 */

void *chained_hash_search(hash_table ht, void *element, hash_function f,
                          sc_comparator c);

/*
 * chained_hash_delete removes the element from ht that would be found
 * with chained_hash_search.  It uses the deletor function d to purge
 * the data found.  If deletor is NULL, the purging is not performed.
 * Comparator "c" is used to do the matching within the list. This function
 * returns 1 if an element was deleted, and 0 otherwise.
 */

int chained_hash_delete(hash_table ht, void *element, hash_function f,
                          deletor d, sc_comparator c);


/*************************************************/
/* Filename:  AVL_code.h                         */
/*************************************************/

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

typedef struct AVL_tree_st {
    void                *data;
    int		             bal;
    struct AVL_tree_st	*left;
    struct AVL_tree_st	*right;
    struct AVL_tree_st	*parent;
} *AVL_tree, AVL_tree_element;


/**** AVL_comparator: if node > comparison return 1, 
                      if node < comparison return -1,
                      if equal return 0
      AVL_deletor: free any space taken up by data ****/
typedef int  (*AVL_comparator)(void *node, void *comparison);
typedef void (*AVL_deletor)(void *deleteMe);

/* these functions return 0 on success, and a negative number on failure */
int      Tree_Add(AVL_tree *addToMe, void *addMe, AVL_comparator theComp);
int      Tree_Delete(AVL_tree *deleteFromMe, void *deleteMe,
                     AVL_comparator theComp, AVL_deletor theDel);
int      Tree_Destroy(AVL_tree *destroyMe, AVL_deletor theDel);

/* these functions return a (+ve) pointer on success, and NULL on failure */
AVL_tree Tree_Search(AVL_tree searchMe, void *searchForMe, AVL_comparator theComp);
AVL_tree Tree_First(AVL_tree searchMe);
AVL_tree Tree_Last(AVL_tree searchMe);
AVL_tree Tree_Next(AVL_tree searchMe);


#ifdef __cplusplus
}
#endif

#endif
