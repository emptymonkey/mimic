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

#include <error.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>



int main(int argc, char **argv){

	char *short_name;
	pid_t target, current, last;
	int flag;


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


	target = (pid_t) strtol(argv[1], NULL, 10);


	flag = 0;
	last = 0;
	current = getpid();
	while((current < target) || (!flag &&(target < current))){

		// Catch the case where the target specified is bigger than /proc/sys/kernel/pid_max .
		if(flag && (current < target) && (last < target)){
			fprintf(stderr, "%s error:\tTarget unreachable. Quitting.\n", short_name);
			exit(-1);
		}

		last = current;
		if(!(current = fork())){
			exit(-1);
		}

		if(current < last){
			if(current == -1){
				fprintf(stderr, "fork error.\n");
				exit(-1);
			}

			flag = 1;
		}
	}

	return(0);
}
