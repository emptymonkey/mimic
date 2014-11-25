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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


/*
 * The strategy here is to have an original parent process that holds the foreground for the user.
 * There will then be a loop parent, who is the child of the original parent. The loop parent is
 * responsible for fork()ing children and tracking state. Those children immediately exit.
 *
 * Child death is fairly lightweight. Parent death is not. This is why we but the burden of death
 * on the children and not the parents.
 * 
 * Unfortunately, some systems seem to have a "maximum number of forks per process" of some
 * sort. Because of this, the loop parent will only spawn off MAX_FORKS number of children before
 * killing itself and letting the next child become the new loop parent (thus resetting the max
 * forks possible). 
 *
 * Until I find a way of determining this setting dynamically at runtime, it is for now a CPP #define.
 *
 */

#define MAX_FORKS	1000



int sig_found;

void signal_handler(int signal){
  sig_found = signal;
}



int main(int argc, char **argv){

	char *short_name;
	pid_t target, current, last;
	int flag;
	int count;
	
	char pid_max_buffer[64];
	int pid_max_fd;
	pid_t pid_max;
	
	pid_t original_parent;

	struct sigaction act;


	if((short_name = strrchr(argv[0], '/')) == NULL){
		short_name = argv[0];
	}else{
		short_name++;
	}


	if(argc != 2){
		fprintf(stderr, "\n%s usage: %s TARGET\n", short_name, argv[0]);
		fprintf(stderr, "\tFork proceses until TARGET pid is reached. Happily loops through pid rollover.\n\n");
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

	// The target the user is asking for should be the next pid available for them. Let's decrement
	// target now, so we don't step on it later.
	target--;

	if(target > pid_max){
		error(-1, 0, "error: target is greater than pid_max! Quitting.");
	}

	sig_found = 0;
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;

	if(sigaction(SIGUSR1, &act, NULL) == -1){
		error(-1, errno, "sigaction(%d, %p, NULL)", SIGUSR1, &act);
	}

	original_parent = getpid();

	if((current = fork()) == -1){
		error(-1, errno, "fork()");
	}else if(current){
		pause();
		
		if(sig_found == SIGUSR1){
			exit(0);
		}else{
			error(-1, errno, "pause()");
		}
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
		if(count == MAX_FORKS){

			if((current = fork()) == -1){
				error(-1, errno, "fork()");
			}else if(current){
				exit(1);
			}

			count = 0;
			current = getpid();

		}else{

			if(!(current = fork())){
				exit(2);
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

	kill(original_parent, SIGUSR1);

	return(0);
}
