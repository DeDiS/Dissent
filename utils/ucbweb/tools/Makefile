# COPYRIGHT AND DISCLAIMER
# 
# Copyright (C) 1996-1997 by the Regents of the University of California.
#
# IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY FOR
# DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
# OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY DERIVATIVES THEREOF,
# EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. THIS SOFTWARE IS
# PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE NO
# OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
# MODIFICATIONS.
#
# For inquiries email Steve Gribble <gribble@cs.berkeley.edu>.

CC = gcc
INCLUDE = -I.
CFLAGS = -Wall -g $(INCLUDE)

# Uncomment the following for Solaris
#LIBS = -lsocket -lnsl -lintl -ldl -lm

# Uncomment the following for Linux
LIBS = -ldl -lm

all: showtrace anon_clients timeconvert

showtrace: showtrace.o logparse.o utils.o
	$(CC) -o $@ showtrace.o logparse.o utils.o $(LIBS)

anon_clients: anon_clients.o logparse.o utils.o md5.o
	$(CC) -o $@ anon_clients.o logparse.o utils.o md5.o $(LIBS)

timeconvert: timeconvert.o
	$(CC) -o $@ timeconvert.o $(LIBS) -lm

%.o: %.c utils.h md5.h logparse.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-/bin/rm -f *.o *~ showtrace timeconvert \
	anon_clients core

FORCE:
	;

