#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

// Quick program to set the current pid range to whatever you want it to be.
// Note, if your number is bigger that /proc/sys/kernel/pid_max then you'll infinite loop.
// No, I'm not adding checking for that case. This tool is intended to be very simple.
// Maybe later.

int main(int argc, char **argv){

	pid_t target, current, last;
	int flag;

	if(argc != 2){
		fprintf(stderr, "usage:...\n");
		exit(-1);
	}

	target = (pid_t) strtol(argv[1], NULL, 10);

	flag = 0;
	last = 0;
	current = getpid();
	while((current < target) || (!flag &&(target < current))){

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

		printf("DEBUG: current: %d\n", current);
	}

	return(0);
}
