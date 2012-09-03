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
 * utils.c --
 *
 * This file provides utility routines for the core icp functions.
 * Included are:
 *
 *   o linked list routines
 *   o hash table routines
 *   o socket convenience routines
 *   o time munging routines
 *   o thread-safe strtok
 *   o thread-unsafe AVL trees (with dorky deletion)
 *
 * $Id: utils.c,v 1.15 1997/02/27 00:58:32 gribble Exp $
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netdb.h>
#ifdef _AIX
#include <sys/select.h>
#endif

#include "utils.h"

/*
 *  Case-insensitive version of strstr()
 */


const char *
strcasestr(const char *string, const char *substr)
{
  int str_len, substr_len, cmplen, i;
  const char *ptr;

  str_len = strlen(string);
  substr_len = strlen(substr);
  cmplen = str_len - substr_len + 1;

  for (ptr = string, i=0; i<cmplen; i++, ptr++) {
    if (strncasecmp(ptr, substr, substr_len) == 0)
      return ptr;
  }
  return NULL;
}


/*
 ************* Dump out the hexification of the buffer ***********
 */
void dump_buf(FILE *std, char *buf, int retlen)
{
  int i, j;

  for (i=0; i<retlen/5; i++) {
    for (j=0; j<5; j++) {
      fprintf(std, "%.02x ", *(buf + (unsigned) 5*i + j));
    }
    fprintf(std, "     ");
    for (j=0; j<5; j++) {
      fprintf(std, "%c ", *(buf + (unsigned) 5*i + j));
    }
    fprintf(std, "\n");
  }
  if (retlen % 5 != 0) {
    for (j=0; j < retlen % 5; j++) {
      fprintf(std, "%.02x ", *(buf + (unsigned) 5*(retlen/5) + j));
    }
    fprintf(std, "     ");
    for (j=0; j<5; j++) {
      fprintf(std, "%c ", *(buf + (unsigned) 5*i + j));
    }
    fprintf(std, "\n");
  }
}

/*
 ************* Time munging utilities *****************
 */

tv_time  tv_timeadd(tv_time t1, tv_time t2)
{
  tv_time ret;

  ret.tv_sec = t1.tv_sec + t2.tv_sec;
  ret.tv_usec = t1.tv_usec + t2.tv_usec;
  if (ret.tv_usec > 1000000L) {
    ret.tv_sec += 1;
    ret.tv_usec -= 1000000L;
  }
  return ret;
}

tv_time  tv_timesub(tv_time t1, tv_time t2)
{
  tv_time ret;

  if (t2.tv_usec > t1.tv_usec) {
    t1.tv_usec += 1000000;
    t2.tv_sec += 1;
  }
  ret.tv_sec = t1.tv_sec - t2.tv_sec;
  ret.tv_usec = t1.tv_usec - t2.tv_usec;
  return ret;
}

tv_time  tv_timemul(tv_time t1, double mult)
{
  tv_time ret;
  double  rsec;
  double  rusec;

  rsec = mult * ((double) t1.tv_sec);
  rusec = mult * ((double) t1.tv_usec);

  ret.tv_sec = rsec;
  ret.tv_usec = rusec;

  ret.tv_usec += ((double) 1000000.0 * (rsec - (double) ret.tv_sec));
  while (ret.tv_usec > 1000000) {
    ret.tv_usec -= 1000000;
    ret.tv_sec += 1;
  }
  return ret;
}

int      tv_timecmp(tv_time t1, tv_time t2)
{
  if (t1.tv_sec > t2.tv_sec)
     return 1;
  if (t1.tv_sec < t2.tv_sec)
     return -1;
  if (t1.tv_usec > t2.tv_usec)
     return 1;
  if (t1.tv_usec < t2.tv_usec)
     return -1;
  return 0;
}

ts_time  ts_timeadd(ts_time t1, ts_time t2)
{
  ts_time ret;

  ret.tv_sec = t1.tv_sec + t2.tv_sec;
  ret.tv_nsec = t1.tv_nsec + t2.tv_nsec;
  if (ret.tv_nsec > 1000000000L) {
    ret.tv_sec += 1;
    ret.tv_nsec -= 1000000000L;
  }
  return ret;
}
ts_time  ts_timesub(ts_time t1, ts_time t2)
{
  ts_time ret;

  if (t2.tv_nsec > t1.tv_nsec) {
    t1.tv_nsec += 1000000000;
    t2.tv_sec += 1;
  }
  ret.tv_sec = t1.tv_sec - t2.tv_sec;
  ret.tv_nsec = t1.tv_nsec - t2.tv_nsec;
  return ret;
}

ts_time  ts_timemul(ts_time t1, double mult)
{
  ts_time ret;
  double  rsec;
  double  rnsec;

  rsec = mult * ((double) t1.tv_sec);
  rnsec = mult * ((double) t1.tv_nsec);

  ret.tv_sec = rsec;
  ret.tv_nsec = rnsec;

  ret.tv_nsec += ((double) 1000000000.0 * (rsec - (double) ret.tv_sec));
  while (ret.tv_nsec > 1000000000) {
    ret.tv_nsec -= 1000000000;
    ret.tv_sec += 1;
  }
  return ret;
}

int      ts_timecmp(ts_time t1, ts_time t2)
{
 if (t1.tv_sec > t2.tv_sec)
     return 1;
  if (t1.tv_sec < t2.tv_sec)
     return -1;
  if (t1.tv_nsec > t2.tv_nsec)
     return 1;
  if (t1.tv_nsec < t2.tv_nsec)
     return -1;
  return 0;
}

/*
 ************* Thread-safe strtok routines and state *************
 */

ts_strtok_state *ts_strtok_init(char *string)
{
  ts_strtok_state *retval;

  if (string == NULL)
    return NULL;

  retval = (ts_strtok_state *) malloc(sizeof(ts_strtok_state));
  if (retval == NULL)
    return NULL;

  retval->string_dupe = strdup(string);
  if (retval->string_dupe == NULL) {
    free(retval);
    return NULL;
  }
  retval->nxt_ptr = retval->string_dupe;
  retval->chars_remaining = strlen(retval->string_dupe);

  return retval;
}

char *ts_strtok(char *matching, ts_strtok_state *state)
{
  int len1, len2;
  char *tmpo;

  if ((matching == NULL) || (state == NULL) || (state->chars_remaining <= 0))
    return NULL;

  len1 = strspn(state->nxt_ptr, matching);
  if (len1 > state->chars_remaining) {
    return NULL;
  }

  tmpo = state->nxt_ptr + (unsigned) len1;
  len2 = strcspn(tmpo, matching);
  if (len2+len1 > state->chars_remaining) {
    return NULL;
  }
  *(tmpo+len2) = '\0';
  state->nxt_ptr = tmpo + len2 + 1;       /* +1 for the null */
  state->chars_remaining -= len1+len2+1;  /* +1 for the null */
  return tmpo;
}

int ts_strtok_finish(ts_strtok_state *state)
{
  if (state) {
    if (state->string_dupe)
      free(state->string_dupe);
    free(state);
  }
  return 1;
}

/************* A really dumb implementation of strnstr ***********/
char *dumb_strnstr(char *str, char *substr, int n)
{
  int i, substrlen, ml;
  char *tmp;

  substrlen = strlen(substr);

  for (i=0,tmp=str; i<=n-substrlen; i++, tmp++) {
    if (*tmp == '\0')
      return NULL;
    if ( (ml = memcmp(tmp, substr, substrlen)) == 0)
      return tmp;
  }
  return NULL;
}

/********* Socket convenience routines ***********/

int correct_write(int s, char *data, int len)
{
  int sofar, ret;
  char *tmp;

  if (len == -1) 
    len = strlen(data);
  
  sofar = 0;
  while (sofar != len) {
    tmp = data + (unsigned long) sofar;
    ret = write(s, tmp, len-sofar);
    if (ret <= 0) {
      if (! ((ret == -1) && ((errno == EAGAIN) || (errno == EINTR))) )
	/* BUG:: What if another thread generates an error and trounces errno? */
	return ret;
    } else
      sofar += ret;
  }
  return len;
}

int correct_read(int s, char *data, int len)
{
  int sofar, ret;
  char *tmp;

  sofar = 0;
  while(sofar != len) {
    tmp = data + (unsigned long) sofar;
    ret = read(s, tmp, len-sofar);
    if (ret <= 0) {
      if (! ((ret == -1) && ((errno == EAGAIN) || (errno == EINTR))) )
	/* BUG:: What if another thread generates an error and trounces errno? */
	return ret;
    } else
      sofar += ret;
  }
  return len;
}

int saccept(int s)
{
    struct sockaddr_in from;
    int     fromlen;
    int     ns;

    fromlen = sizeof (from);
    if ((ns = accept (s, (void *) &from, &fromlen)) < 0)
        return -1;
    return ns;
}

int nbaccept(int s, int *rs)
{
   fd_set fdset;
   static struct timeval timeout = {0, 0};  /* For a poll */
   int    val, socket_talk;

   FD_ZERO(&fdset);
   FD_SET(s, &fdset);
   val = select(FD_SETSIZE, (fd_set *) &fdset, NULL, NULL, &timeout);

   if ((val == 0) || (val == -1))
     return val;

   /* The socket is ready for an accept, so perform it. */
   socket_talk = saccept(s);
   if (socket_talk < 0)
   {
      if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
         return 0;
      return -1;  /* ERROR */
   }
   *rs = socket_talk;
   return 1;  /* SUCCESS */

}

int sconnect(char *hostname, char *servicename)
{
    struct sockaddr_in remote;
    struct sockaddr_in local;
    int     s;
    int     protonum;

#ifdef DEBUG
    printf("(glomopTk_utils.c) make_inetaddr for %s %s\n", hostname,
	   servicename);
#endif
    if (make_inetaddr (hostname, servicename, &remote) < 0)
        return -1;

    if ((protonum = protonumber ("tcp")) < 0)
        return -1;

#ifdef DEBUG
    printf("(utils.c) socket for protonum %d\n", protonum);
#endif
    if ((s = socket (PF_INET, SOCK_STREAM, protonum)) < 0)
        return -1;
    
    if (make_inetaddr ((char *) 0, (char *) 0, &local) < 0)
        return -1;

    if (bind (s, (struct sockaddr *) &local, sizeof (local)) < 0)
        return -1;

#ifdef DEBUG
    printf("(utils.c) connecting..\n");
#endif
    if (connect (s, (struct sockaddr *) &remote, sizeof (remote)) < 0)
        return -1;

    return s;
}

int slisten(char *servicename)
{
    struct sockaddr_in inaddr;
    int     s, i=1;
    int     protonum;

    if ((protonum = protonumber ("tcp")) < 0)
        return -1;

    if ((s = socket (PF_INET, SOCK_STREAM, protonum)) < 0)
        return -1;

    /* Put the REUSEADDR and KEEPALIVE sockopts in */
    i=1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *) &i,
		   sizeof(int)) != 0) {
      return -1;
    }
    i=0;
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *) &i,
		   sizeof(int)) != 0) {
      return -1;
    }

    if (make_inetaddr ((char *) 0, servicename, &inaddr) < 0)
        return -1;

    if (bind (s, (struct sockaddr *) &inaddr, sizeof (inaddr)) < 0)
        return -1;

    if (listen (s, 4) < 0)
        return -1;

    return s;
}

int sportnum(int s)
{
    struct sockaddr sockname;
    int     len;

    len = sizeof (sockname);
    if (getsockname (s, &sockname, &len) < 0)
        return -1;

    if (sockname.sa_family != AF_INET)
        return -1;

    return ((struct sockaddr_in *) (&sockname))->sin_port;
}

int make_inetaddr(char *hostname, char *servicename, 
                  struct sockaddr_in *inaddr)
{
    struct hostent *host;
    struct servent *service;

    inaddr->sin_family = AF_INET;
    if (hostname == 0)
      inaddr->sin_addr.s_addr = 0;
    else if (isdigit (*hostname))
      inaddr->sin_addr.s_addr = inet_addr(hostname);
    else
    {
        if ((host = gethostbyname(hostname)) == 0)
        {
	  /*fprintf(stderr, "Unknown host in make_inetaddr..\n");*/
            return -1;
        }
        if (host->h_addrtype != AF_INET)
        {
            fprintf(stderr, "Unknown af in make_inetaddr\n");
            return -1;
        }
        memcpy(&inaddr->sin_addr.s_addr, host->h_addr, host->h_length);
    }  

    if (servicename == 0)
      inaddr->sin_port = 0;
    else if (isdigit (*servicename))
      inaddr->sin_port = htons(atoi (servicename));
    else
    {
        if ((service = getservbyname (servicename, "tcp")) == 0)
        {
            fprintf(stderr, "Unknown service in make_inetaddr.\n");
            return -1;
        }
        inaddr->sin_port = service->s_port;
    }
    return 0;
}

int protonumber(char *protoname)
{
    struct protoent *proto;

    if ((proto = getprotobyname (protoname)) == 0)
        return -1;

    return proto->p_proto;
}

int test_readable(int s)
{
   fd_set fdset;
   static struct timeval timeout = {0, 0};  /* For a poll */
   int    val;

   FD_ZERO(&fdset);
   FD_SET(s, &fdset);
   val = select(FD_SETSIZE, (fd_set *) &fdset, NULL, NULL, &timeout);

   if (val > 0)
      return 1;

   return val;
}

int test_writable(int s)
{
   fd_set fdset;
   static struct timeval timeout = {0, 0};  /* For a poll */
   int    val;

   FD_ZERO(&fdset);
   FD_SET(s, &fdset);
   val = select(FD_SETSIZE, NULL, (fd_set *) &fdset, NULL, &timeout);

   if (val > 0)
      return 1;

   return val;
}

/********* Linked-list utilities ***********/

#define LL_HEAPSIZE 50
static ll heap_o_ll = NULL;   /* Heap of free nodes for alloc and dealloc */

/* Some private functions */
ll   Allocate_ll(void);
void Free_ll(ll freeMe);

int ll_add_to_end(ll *addToMe, void *data)
{
   ll temp;

   temp = *addToMe;
   if (temp == NULL)
   {
      *addToMe = temp = Allocate_ll();
      temp->data = data;
      temp->prev = temp->next = NULL;
      return 1;
   }

   while (temp->next != NULL)
     temp = temp->next;

   temp->next = Allocate_ll();
   (temp->next)->prev = temp;
   (temp->next)->next = NULL;
   (temp->next)->data = data;
   return 1;
}

int ll_add_to_start(ll *addToMe, void *data)
{
   ll temp;

   temp = *addToMe;
   if (temp == NULL)
   {
      *addToMe = temp = Allocate_ll();
      temp->data = data;
      temp->prev = temp->next = NULL; 
      return 1;
   }

   temp->prev = Allocate_ll();
   (temp->prev)->next = temp;
   (temp->prev)->prev = NULL;
   (temp->prev)->data = data;
   *addToMe = temp->prev;

   return 1;

}

ll  ll_find(ll *findInMe, void *data, int (*compare)(void *d1, void *d2))
{
   ll temp = *findInMe;

   while (temp != NULL)
   {
     if (compare(data, temp->data) == 0)  /* ie the same */
        return temp;
     
     temp = temp->next;
   }
   return temp;
}

int ll_sorted_insert(ll *insertme, void *data, 
		     int (*compare)(void *d1, void *d2))
{
  ll temp = *insertme, addEl;

  while (temp != NULL) {
    if (compare(data, temp->data) <= 0) {/* ie. the same or smaller */
      /* insert before temp */
      addEl = Allocate_ll();
      addEl->data = data;
      addEl->prev = temp->prev;
      addEl->next = temp;
      temp->prev = addEl;
      if (addEl->prev == NULL)
	*insertme = addEl;
      else
	(addEl->prev)->next = addEl;
      return 1;
    }
    temp = temp->next;
  }
  
  /* We hit the end, so add to the end */
  return ll_add_to_end(insertme, data);
}

int  ll_del(ll *delFromMe, void *data, int (*compare)(void *d1, void *d2),
            void (*nukeElement)(void *nukeMe))
{
   ll temp = *delFromMe;

   while (temp != NULL)
   {
      if (compare(data, temp->data) == 0)  /* ie the same */
      {
         if (temp->prev != NULL)
           (temp->prev)->next = temp->next;

         if (temp->next != NULL)
           (temp->next)->prev = temp->prev;

         if (temp == *delFromMe)
            *delFromMe = temp->next;

         if (nukeElement != NULL)
            nukeElement(temp->data);
         Free_ll(temp);
         return 1;
      }
      temp = temp->next;
   }
   return 0;
}

int ll_delfirst(ll *delFromMe, void (*nukeElement)(void *nukeMe))
{
   ll temp = *delFromMe;

   if (temp == NULL)
      return 0;

   if (temp->prev != NULL)
     (temp->prev)->next = temp->next;

   if (temp->next != NULL)
     (temp->next)->prev = temp->prev;

   if (temp == *delFromMe)
     *delFromMe = temp->next;

   if (nukeElement != NULL)
     nukeElement(temp->data);
   Free_ll(temp);
   return 1;
}

int ll_destroy(ll *destroyMe, void (*nukeElement)(void *nukeMe))
{
   ll temp = *destroyMe, next;

   while (temp != NULL)
   {
      next = temp->next;
      if (nukeElement != NULL)
         nukeElement(temp->data);
      Free_ll(temp);
      temp = next;
   }
   *destroyMe = NULL;
   return 1;
}

ll   Allocate_ll(void)
{
   int counter;
   ll  temp_pointer;

   /* if heap is null, am out of ll elements and must allocate more */
   if (heap_o_ll == NULL)
   {
      heap_o_ll = (ll_node *) malloc(LL_HEAPSIZE * sizeof(ll_node));
      if (heap_o_ll == NULL)
      {
         fprintf(stderr, "Out of memory in Allocate_ll!\n");
         exit(1);
      }
      for (counter=0; counter < LL_HEAPSIZE - 1; counter++)
      {
          (heap_o_ll + counter)->data = NULL;
          (heap_o_ll + counter)->prev = NULL;
          (heap_o_ll + counter)->next = (heap_o_ll + counter + 1);
      }
      (heap_o_ll + LL_HEAPSIZE - 1)->next = NULL;
   }

   /* Have a workable heap.  Splice off top and return pointer. */
   temp_pointer = heap_o_ll;
   heap_o_ll = heap_o_ll->next;
   temp_pointer->next = NULL;
   return temp_pointer;
}

void Free_ll(ll freeMe)
{
   freeMe->next = heap_o_ll;
   heap_o_ll = freeMe;
}


int ll_build(ll *buildMe, char *buildFromMe)
{
 /* Takes string of form [a, b, c, d, e] and builds linked list with
    elements from the string.  Malloc's space for new linked list element
    strings. */

    char *end, *start, *data, *temp;

    data = (char *) malloc(sizeof(char) * (strlen(buildFromMe)+1));
    if (data == NULL)
    {
      fprintf(stderr, "Out of memory in ll_build!\n");
      return 0;
    }
    strcpy(data, buildFromMe);
    start = end = data + 1;
    
    while ((*end != ']') && (*end != '\0'))
    {
      while (*start == ' ')
      {
        start++;  end++;
      }

      if (*end == ',')
      {
          *end = '\0';
          temp = (char *) (malloc(sizeof(char) * (strlen(start)+1)));
          if (temp == NULL)
          {
             fprintf(stderr, "Out of memory in ll_build!\n");
             return 0;
          }
          strcpy(temp, start);
          ll_add_to_end(buildMe, (void *) temp);
          start = end + 1;
      }
      end++;
    }
    *end = '\0';
    temp = (char *) (malloc(sizeof(char) * (strlen(start)+1)));
    if (temp == NULL)
    {
       fprintf(stderr, "Out of memory in ll_build!\n");
       return 0;
    }
    strcpy(temp, start);
    ll_add_to_end(buildMe, (void *) temp);
    free(data);
    return 1;
}

/****************** Hash table routines *****************/

int chained_hash_create(int num_slots, hash_table *rt)
{
   hash_table  retval;
   hash_el    *sArray;
   int i;

   /* Creating a chained hash table is as simple as allocating room
      for all of the slots. */
   
   sArray = retval.slot_array = (hash_el *) malloc(num_slots*sizeof(hash_el));
   if (retval.slot_array == NULL)
      return -1;

   retval.num_elements = num_slots;
   *rt = retval;

   /* Initialize all slots to have a null entry */
   for (i=0; i<num_slots; i++)
     sArray[i] = NULL;

   return 0;
}

int chained_hash_destroy(hash_table ht, deletor d)
{
   int      i, numEl;
   hash_el *sArray;

   /* Destroying a hash table first implies destroying all of the
      lists in the table, then freeing the table itself. */

   for (i=0, numEl=ht.num_elements, sArray=ht.slot_array; i<numEl; i++)
   {
      if (sArray[i] != NULL)
      {
         /* We must destroy the list in this slot */
         ll_destroy(&(sArray[i]), d);
         sArray[i] = NULL;
      }
   }
   free(sArray);
   return 0;
}

int chained_hash_insert(hash_table ht, void *element, hash_function f)
{
   int  slotnum;
   ll  *slotList;

   slotnum = f(element, ht.num_elements);
   if (! ((slotnum >= 0) && (slotnum < ht.num_elements)) )
     return -1;   /* f is bad */

   slotList = &(ht.slot_array[slotnum]);
   if (ll_add_to_start(slotList, element) != 1)
     return -1;   /* list insert failed */

   return 0;
}

void *chained_hash_search(hash_table ht, void *element, hash_function f,
                          sc_comparator c)
{
   ll   *slotList, foundEl;
   int   slotnum;

#ifdef DEBUG
   printf("chained_hash_search: about to f element, numelements %d\n", ht.num_elements);
#endif

   slotnum = f(element, ht.num_elements);

#ifdef DEBUG
   printf("f() returned slotnum %d\n", slotnum);
#endif

   if (! ((slotnum >= 0) && (slotnum < ht.num_elements)) )
     return NULL;  /* f is bad */

#ifdef DEBUG
   printf("in chs: slotnum %d\n", slotnum);
#endif
   slotList = &(ht.slot_array[slotnum]);
   if (slotList == NULL)
     return NULL;  /* no list, no element */

#ifdef DEBUG
   printf("about to ll_find on slotList.\n");
#endif
   foundEl = ll_find(slotList, element, c);
   if (foundEl == NULL)
     return NULL;
   return foundEl->data;
}

int chained_hash_delete(hash_table ht, void *element, hash_function f,
                          deletor d, sc_comparator c)
{
   ll   *slotList;
   int   slotnum;

   slotnum = f(element, ht.num_elements);
   if (! ((slotnum >= 0) && (slotnum < ht.num_elements)) )
     return 0;  /* f is bad */

   slotList = &(ht.slot_array[slotnum]);
   if (slotList == NULL)
     return 0;  /* no list, no element */

   return ll_del(slotList, element, c, d);
}

/************************************************
 Filename:  AVL_code.c                          *
 DEFINITELY NOT NOT NOT THREAD SAFE             *
 ***********************************************/

#define AVL_ALLOC_NUM 200  /* number of elements to allocate per heap chunk */

/*** global variables ***/

/*** Local function prototypes ***/
AVL_tree Allocate_AVL_tree(void);
void     Free_AVL_tree(AVL_tree freeMe);

/*** Publically accessible functions ***/

int Tree_Add(AVL_tree *addToMe, void *addMe, AVL_comparator theComp)
{
    static int       checkBalance = FALSE;
    static AVL_tree	 parent = NULL;
    AVL_tree        *addTree = addToMe;

    if (*addTree == NULL)  /* Add in a new leaf... */
    {
        *addTree = Allocate_AVL_tree();
        (*addTree)->data = addMe;
        (*addTree)->bal = 0;
        (*addTree)->left = (*addTree)->right = NULL;
        (*addTree)->parent = parent;
        checkBalance = TRUE; /* whether balance should be checked */
        parent = NULL;
        return 0;
    }
    else
        if ( theComp( (*addTree)->data, addMe) > 0 )   // ie. (*addTree)->data > addMe
        {   
            parent = *addTree;
            if ( Tree_Add(&((*addTree)->left), addMe, theComp) != 0 )
            {   checkBalance = FALSE;    return -1;  }
            if (checkBalance == TRUE)  /* CHECK FOR REBALANCING -
                                          LEFT INSERTION */
            {
                switch( (*addTree)->bal) {
                    case 1 :  (*addTree)->bal = 0;
                              checkBalance = FALSE;  return 0;
                    case 0 :  (*addTree)->bal = -1;
                              checkBalance = TRUE;  return 0;
                    case -1:
                    {  AVL_tree p = (*addTree)->left;
                       switch (p->bal) {
                           case -1: {  /* LL ROTATION */
                                AVL_tree q = *addTree;
                                AVL_tree r = p->right;
                                p->parent = q->parent;
                                p->right = q;
                                q->parent = p; q->left = r;
                                if (r != NULL)
                                    r->parent = q;
                                *addTree = p;  (*addTree)->bal = 0;
                                q->bal = 0;  checkBalance = FALSE;
                                return 0;  }
                           case +1: {  /* LR ROTATION */
                                AVL_tree m = *addTree;
                                AVL_tree q = p->right;
                                AVL_tree s = q->left;
                                AVL_tree u = q->right;
                                q->parent = m->parent;
                                m->parent = q;
                                p->parent = q;
                                if (s != NULL)
                                   s->parent = p;
                                if (u != NULL)
                                   u->parent = m;
                                p->right = s;  q->left = p;
                                q->right = m;  m->left = u;
                                *addTree = q;
                                if (q->bal == 0)
                                {
                                   q->bal = 0;
                                   p->bal = 0;
                                   m->bal = 0;
                                }
                                else if (q->bal == -1)
                                {
                                   q->bal = 0;
                                   p->bal = 0;
                                   m->bal = 1;
                                   
                                }
                                else if (q->bal == 1)
                                {
                                   q->bal = 0;
                                   p->bal = -1;
                                   m->bal = 0;
                                }
                                checkBalance = FALSE;  return 0; }
                           default: exit(1);
                     } } }
            }
            else
            {   checkBalance = FALSE;  return 0; }
        }
        else
        if ( theComp( (*addTree)->data, addMe) < 0 ) /* ie. (*addTree)->data < addMe */
        {
            parent = *addTree;
            if ( Tree_Add(&((*addTree)->right), addMe, theComp) != 0 )
            {  checkBalance = FALSE;  return -1; }
            if (checkBalance == TRUE)
            {    /* Check for rebalancing - right insertion */
                switch ( (*addTree)->bal) {
                    case -1:  (*addTree)->bal = 0;
                              checkBalance = FALSE;  return 0;
                    case 0 :  (*addTree)->bal = 1;
                              checkBalance = TRUE;  return 0;
                    case 1 :
                    {  AVL_tree p = (*addTree)->right;
                       switch (p->bal) {
                           case -1: {  /*i RL ROTATION */
                             AVL_tree m = *addTree;
                             AVL_tree q = p->left;
                             AVL_tree r = q->right;
                             AVL_tree s = q->left;
                             q->parent = m->parent;
                             m->parent = q;
                             p->parent = q;
                             if (s != NULL)
                                s->parent = m;
                             if (r != NULL)
                                r->parent = p;
                             m->right = s;  q->left = m;
                             q->right = p;  p->left = r;
                             (*addTree) = q;
                                if (q->bal == 0)
                                {
                                   q->bal = 0;
                                   p->bal = 0;
                                   m->bal = 0;
                                }
                                else if (q->bal == -1)
                                {
                                   q->bal = 0;
                                   p->bal = 1;
                                   m->bal = 0;
                                   
                                }
                                else if (q->bal == 1)
                                {
                                   q->bal = 0;
                                   p->bal = 0;
                                   m->bal = -1;
                                }
                             checkBalance = FALSE;
                             return 0; }
                           case +1: {  /* RR ROTATION */
                             AVL_tree q = (*addTree);
                             AVL_tree r = p->left;
                             p->parent = q->parent;
                             q->parent = p;
                             if (r != NULL)
                                r->parent = q;
                             p->left = q;  q->right = r;
                             (*addTree) = p;  (*addTree)->bal = 0;
                             q->bal = 0;  checkBalance = FALSE;
                             return 0; }
                       }
                    }
                }
            }
            else
            {  checkBalance = FALSE;  return 0; }
        }
        else    /* key already exists - bomb out */
        {  checkBalance = FALSE;  return -1;  }

    return 0;
}

int      Tree_Delete(AVL_tree *deleteFromMe, void *deleteMe,
                     AVL_comparator theComp, AVL_deletor theDel)
{
   /* A simplified version of an AVL_delete algorithm.  This procedure will
      instead do a regular binary tree deletion  */

    AVL_tree         tempTree, tempTreeX, Z;
    static AVL_tree *root = NULL;

    Z = *deleteFromMe;

    if (*deleteFromMe == NULL)  /* hit a leaf.  bomb out */
    {    root = NULL;
         return -1;
    }

    if (root == NULL)
        root = deleteFromMe;

    if ( theComp((*deleteFromMe)->data, deleteMe) > 0 ) /* ie. (*deleteFromMe)->data > deleteMe */
       return Tree_Delete(&((*deleteFromMe)->left), deleteMe, theComp, theDel);
    else
    {
        if ( theComp((*deleteFromMe)->data, deleteMe) < 0) /* ie. (*deleteFromMe)->data < deleteMe */ 
           return Tree_Delete(&((*deleteFromMe)->right), deleteMe, theComp, theDel);
        else
        {
            theDel((*deleteFromMe)->data);   /* Call the deletor function */
            
            /* we've found the node to delete - three cases */
            if (  (((*deleteFromMe)->left) == NULL) ||
                  (((*deleteFromMe)->right) == NULL) )
                tempTree = *deleteFromMe;
            else
                tempTree = Tree_Next(*deleteFromMe);

            if ( tempTree->left != NULL)
                tempTreeX = tempTree->left;
            else
                tempTreeX = tempTree->right;

            if (tempTreeX != NULL)
                tempTreeX->parent = tempTree->parent;

            if (tempTree->parent == NULL)   /* ie root, replace all */
                *root = tempTreeX;
            else
            {
                if ( tempTree == ((tempTree->parent)->left) )
                    ((tempTree->parent)->left) = tempTreeX;
                else
                    ((tempTree->parent)->right) = tempTreeX;
            }

            if (tempTree != Z)
            {
              /* splice successor back in */
              (*deleteFromMe)->data = tempTree->data;
            }

            Free_AVL_tree(tempTree);
            root = NULL;
            return 0;

        }
    }
}

int Tree_Destroy(AVL_tree *destroyMe, AVL_deletor theDel)
{
   if (*destroyMe == NULL)
      return 0;
   
   Tree_Destroy( &((*destroyMe)->left), theDel);
   Tree_Destroy( &((*destroyMe)->right), theDel);
   
   theDel( (*destroyMe)->data );
   Free_AVL_tree(*destroyMe);
   *destroyMe = NULL;
   return 0;
}

AVL_tree Tree_Search(AVL_tree searchMe, void *searchForMe, AVL_comparator theComp)
{
    if (searchMe == NULL)  /* didn't find it! */
       return NULL;

    if (theComp(searchMe->data, searchForMe) > 0 ) /* ie. searchMe->data > searchForMe */
       return Tree_Search(searchMe->left, searchForMe, theComp);

    if (theComp(searchMe->data, searchForMe) < 0 ) /* ie. searchMe->data < searchForMe */
       return Tree_Search(searchMe->right, searchForMe, theComp);

    /* aha! found correct key */
    return searchMe;
}

AVL_tree Tree_First(AVL_tree searchMe)
{
   AVL_tree retTree = searchMe;
   
   if (retTree == NULL)
      return NULL;
   
   while (retTree->left != NULL)
      retTree = retTree->left;
   
   return retTree;
}

AVL_tree Tree_Last(AVL_tree searchMe)
{
   AVL_tree retTree = searchMe;
   
   if (retTree == NULL)
      return NULL;
   
   while (retTree->right != NULL)
      retTree = retTree->right;
   
   return retTree;
}

AVL_tree Tree_Next(AVL_tree searchMe)
{
    AVL_tree    tempTree;

    if ((searchMe->right) != NULL) /* aha! swoop down to min  of right subtree */
    {
        tempTree = searchMe->right;
        while ((tempTree->left) != NULL)
           tempTree = tempTree->left;
        return tempTree;
    }
   
    /* right is null - find lowest ancestor whose left child is also ancestor of x */
    tempTree = searchMe->parent;
    while ( (tempTree != NULL) && (searchMe == tempTree->right) )
    {
       searchMe = tempTree;
       tempTree = tempTree->parent;
    }
    return tempTree;
}


/****** 
  Local functions - heap maintenance code
******/

AVL_tree Allocate_AVL_tree(void)
{
    AVL_tree  temp_pointer;

    temp_pointer = (AVL_tree) malloc(sizeof(AVL_tree_element));
    if (temp_pointer == NULL) {
      fprintf(stderr, "Out of memory in Allocate_AVL_tree!\n");
      exit(-1);
    }
    return temp_pointer;
}

void Free_AVL_tree(AVL_tree freeMe)
{
    /* assume that data has been freed */
    if (freeMe == NULL)
       return;

    free(freeMe);
}
