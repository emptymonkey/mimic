/***********************************************************************************************************************
 *
 * set_target_pid
 *
 *	2014-10-09
 *
 *	emptymonkey's tool for process pid alignment.
 *
 *
 *	Purpose:
 *		This tool will exhaust pids until the current pids being issued are at (or near) your target.
 *		This is very handy when combined with the mimic tool for covert execution, as it will bury the mimiced process
 *		in an otherwise unlooked range. 
 *
 *	Notes:
 *		The linux kernel reserves the first three-hundered pids for kernel threads. If you target below that, 
 *		set_target_pid will get you as close as possible to the boundary.
 *
 **********************************************************************************************************************/

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


// Some versions of Linux seem to have a "max fork()s for a process".
// I can't find exactly where this is set, so for now, here is a 
// TUNABLE constant that can be used to control how often the parent dies.
// Fork() then killing parent is very processer intensive. Fork() then
// killing child is not. So, kill as many children as TUNABLE allows,
// then kill the parent to reset the OS max fork() per proc count.
#define TUNEABLE 1000


int main(int argc, char **argv){

	char *short_name;
	pid_t target, current, last;
	int flag;
	int count;
	
	char pid_max_buffer[64];
	int pid_max_fd;
	pid_t pid_max;
	


	if((short_name = strrchr(argv[0], '/')) == NULL){
		short_name = argv[0];
	}else{
		short_name++;
	}


	if(argc != 2){
		fprintf(stderr, "\n%s usage: %s TARGET\n", short_name, argv[0]);
		fprintf(stderr, "\tFork-kills children until TARGET pid is reached. Happily loops through pid rollover.\n\n");
		exit(-1);
	}

	memset(pid_max_buffer, 0, 64);
	if((pid_max_fd = open("/proc/sys/kernel/pid_max", O_RDONLY)) == -1){
		error(-1, errno, "open(\"/proc/sys/kernel/pid_max\")");
	}

	if(read(pid_max_fd, pid_max_buffer, sizeof(pid_max_buffer)) == -1){
		error(-1, errno, "read(%d, %p, %d)", pid_max_fd, pid_max_buffer, (int) sizeof(pid_max_buffer));
	}
	close(pid_max_fd);

	pid_max = (pid_t) strtol(pid_max_buffer, NULL, 10);

	target = (pid_t) strtol(argv[1], NULL, 10);

	if(target > pid_max){
		error(-1, 0, "error: target is greater than pid_max! Quitting.");
	}

	flag = 0;
	last = 0;
	current = getpid();
	count = 0;

	if(current < target){
		flag = 1;
	}

	while((flag && (current < target)) || (!flag && (target < current))){

		last = current;
		if(count == TUNEABLE){

			if((current = fork()) == -1){
				exit(-1);
			}else if(current){
				exit(0);
			}

			count = 0;
			current = getpid();

		}else{

			if(!(current = fork())){
				exit(-1);
			}

		}

		if(current < last){
			if(current == -1){
				printf("error: last pid: %d\n", last);
				exit(-1);
			}

			flag = 1;
		}

		count++;
	}

	return(0);
}
