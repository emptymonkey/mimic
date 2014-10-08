CC = gcc

CFLAGS = -std=gnu99 -Wall -Wextra -Os

LDIR = -L../ptrace_do
IDIR = -I../ptrace_do
LIBS = -lptrace_do

OBJS = string_to_vector.o wordexp_t_to_vector.o 

all: mimic set_target_pid

mimic: mimic.c $(OBJS)
	$(CC) $(CFLAGS) $(IDIR) $(LDIR) $(OBJS) -o mimic mimic.c $(LIBS)

string_to_vector: string_to_vector.c
	$(CC) $(CFLAGS) -c -o string_to_vector.o string_to_vector.c

wordexp_t_to_vector: wordexp_t_to_vector.c
	$(CC) $(CFLAGS) -c -o wordexp_t_to_vector.o wordexp_t_to_vector.c

set_target_pid: set_target_pid.c
	$(CC) $(CFLAGS) -o set_target_pid set_target_pid.c

clean: 
	rm mimic set_target_pid $(OBJS)
