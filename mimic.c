
/***********************************************************************************************************************
 *
 *	mimic
 *
 *
 *	emptymonkey's tool for covert daemon execution. 
 *		Liar, liar, /proc on fire!
 *
 *
 *	2014-09-28
 *
 *
 *	This tool runs in user-space and requires *no* elevated privileges. 
 *
 *	This tool allows a user to run any program and have it appear in the process listings as any other
 *	program. It works by altering the internal process structures in a way to confuse the /proc/PID filesystem. Tools
 *	that report process details gather that information from the /proc/PID entry for that process.
 *
 *
 *	Features:
 *		* Mimic the desired process while maintaining proper internal consistency, ensuring the real process doesn't
 *				believe it's own deception.
 *		* Alter /proc/PID/cmdline to report as the mimic cmdline would.
 *		* Alter /proc/PID/environ to report as the mimic envp would.
 *		* Alter /proc/PID/stat to report as the mimic stat would.
 *
 *	To Do:
 *		* Add /proc/PID/exe support (though this will likely only be usable as root.)
 *		* Add support for remapping the internal memory of the process so that /proc/PID/maps is of no help.
 *
 **********************************************************************************************************************/


#define _GNU_SOURCE


#include <errno.h>
#include <error.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wordexp.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>


#include "libptrace_do.h"


#define DEFAULT_MIMIC "/usr/sbin/apache2 -k start"
#define DEFAULT_ROOT_MIMIC "[kworker/0:0]"

#define SOH_CHAR	0x01
#define NULL_CHAR	0x00


char **wordexp_t_to_vector(wordexp_t *wordexp_t_in);
int key_match(char **vector, char *key_value);
void build_execution_headers(void *local_buffer, void *base_addr, char **argv, char **envp);
int get_vector_byte_count(char **argv);



void usage(){

	fprintf(stderr, "usage: %s -e COMMAND [-m MIMIC] [-b] [-a KEY=VALUE] [-h]\n", program_invocation_short_name);
	fprintf(stderr, "\t-e\tExecute COMMAND.\n");
	fprintf(stderr, "\t-m\tSetup COMMAND to look like MIMIC.\n");
	fprintf(stderr, "\t\t\tDefault for non-root is:\t\"%s\"\n", DEFAULT_MIMIC);
	fprintf(stderr, "\t\t\tDefault for root is:\t\t\"%s\"\n", DEFAULT_ROOT_MIMIC);
	fprintf(stderr, "\t-b\tLaunch COMMAND in the background.\n");
	fprintf(stderr, "\t-a\tAdd / overwrite KEY to the mimic environment with associated VALUE.\n");
	fprintf(stderr, "\t-h\tPrint this helpful message.\n");
	fprintf(stderr, "\n\tNotes:\n");
	fprintf(stderr, "\t\tThe MIMIC environment will be a copy of the COMMAND environment.\n");
	fprintf(stderr, "\t\tThe '_' variable is automatically changed.\n");
	fprintf(stderr, "\t\tThe -a flag can be called multiple times to add / overwrite multiple variables.\n");
	// XXX Add examples.
	fprintf(stderr, "\n\tExamples:\n");

	exit(-1);
}



/***********************************************************************************************************************
 *
 *	main()
 *
 *	Input: Our instructions from the command line, as well as our environment.
 *	Output: An integer representing status.
 *
 *	Purpose: main() runs the show.
 *
 *	Strategy: This is a simple program. The heavy lifting is done using the ptrace_do library. That along with a 
 *		solid understanding of process internals leaves very little left for us to do here. The plan of attack is
 *		as follows:
 *			* Parse the relevant input from the user and do some initialization.
 *			* Fork a child process. (This child will be the exec() point, and is our willing accomplice.)
 *			* The child will request to be ptrace()'d and then proceed to exec() the real binary.
 *			* The parent will connect with the child and initialize its ptrace_do instance.
 *			* The parent will examine the child's state.
 *			* The parent will inject a prctl() PR_SET_NAME request for the child to execute.
 *			* The parent will execute the child, one step at a time, and inspect the child each at step, attempting
 *				to locate main().
 *			* As the child was executed with the mimic argv and envp, the deception was already set up by the kernel.
 *				We must now set up the child's internal state so it doesn't deceive itself.
 *			* The parent will request memory in the remote process.
 *			* The parent will set up that region of memory to hold the execution headers, as you would find at the base
 *				of the stack, consisting of argv, envp, and a NULL auxv.
 *			* The parent will set up some remaining state in the child and detach.
 *
 *	Good-bye and have a good-luck! :)
 *
 **********************************************************************************************************************/
int main(int argc, char **argv, char **envp){

	unsigned int i;
	int retval;

	int opt;

	char *execute_string = NULL, *mimic_string = NULL;
	wordexp_t execute_wordexp_t, mimic_wordexp_t;
	char **execute_argv, **mimic_argv;
	int execute_argc, mimic_argc;
	char **mimic_envp;
	int mimic_envc = 0;

	int child_pid;
	struct ptrace_do *child;

	char **execution_header_local;
	void *execution_header_remote;

	char **local_buffer;
	void *remote_buffer;

	unsigned int execution_header_size;

	char *tmp_string_ptr;

	unsigned long peektext;

	unsigned long argc_stack_val, argv_stack_val, envp_stack_val;
	int status;
	long ret_long;

	struct user_regs_struct test_regs;

	int background = 0;

	int self_exec = 0;

	int tmp_size;

	char **foreground_mimic_argv;
	char soh_string[2];

	char *mimic_short_name;


	if(argv){
		i = 0;
		while(argv[i]){
			if(argv[i][0] == SOH_CHAR){
				self_exec = 1;
				argv[i][0] = NULL_CHAR;
				break;
			}
			i++;
		}
	}

	if(self_exec){
		memset(&argc, i, 1);	

		if((retval = prctl(PR_SET_NAME, argv[i + 1], NULL, NULL, NULL)) == -1){
			fprintf(stderr, "prctl(PR_SET_NAME, %lx, NULL, NULL, NULL): %s\n", \
					(unsigned long) argv[i + 1], strerror(errno));
			exit(-1);
		}
		wait(NULL);
		exit(0);
	}



	// The max size needed of the new env buffer will be:
	//  * size of current env
	//  * plus the size of the max '_' variable (which is PATH_MAX + 3)
	//	* plus the strlen's of the various added environment variables.
	tmp_size = get_vector_byte_count(envp);
	tmp_size += PATH_MAX + 3;

	opterr = 0;
	while ((opt = getopt(argc, argv, "e:m:wa:bh")) != -1) {
		switch (opt) {
			case 'a':
				tmp_size += strlen(optarg) + 1;
		}
	}


	if((mimic_envp = (char **) calloc(tmp_size, sizeof(char))) == NULL){
		fprintf(stderr, "calloc(%d, %d): %s\n", tmp_size, (int) sizeof(char), strerror(errno));
		exit(-1);
	}


	// Now reset and actually handle the options.
	optind = 1;
	opterr = 1;
	while ((opt = getopt(argc, argv, "e:m:wa:bh")) != -1) {

		switch (opt) {
			case 'e':
				execute_string = optarg;
				break;

			case 'm':
				mimic_string = optarg;
				break;

			case 'b':
				background = 1;
				break;

			case 'a':
				if(!key_match(mimic_envp, optarg)){
					mimic_envp[mimic_envc++] = optarg;
				}
				break;

			case 'h':
			default:
				usage();
		}
	}


	if((argc - optind) || !execute_string){
		usage();
	}

	if(!mimic_string){
		if(!getuid()){
			mimic_string = DEFAULT_ROOT_MIMIC;
		}else{
			mimic_string = DEFAULT_MIMIC;
		}
	}

	if(wordexp(execute_string, &execute_wordexp_t, 0)){
		error(-1, errno, "wordexp(%s, %lx, 0)", execute_string, (unsigned long) &execute_wordexp_t);
	}

	if((execute_argv = wordexp_t_to_vector(&execute_wordexp_t)) == NULL){
		error(-1, errno, "wordexp_t_to_vector(%lx)", (unsigned long) &execute_wordexp_t);
	}
	execute_argc = execute_wordexp_t.we_wordc;

	if(wordexp(mimic_string, &mimic_wordexp_t, 0)){
		error(-1, errno, "wordexp(%s, %lx, 0)", mimic_string, (unsigned long) &mimic_wordexp_t);
	}

	if((mimic_argv = wordexp_t_to_vector(&mimic_wordexp_t)) == NULL){
		error(-1, errno, "wordexp_t_to_vector(%lx)", (unsigned long) &mimic_wordexp_t);
	}
	mimic_argc = mimic_wordexp_t.we_wordc;


	if((mimic_short_name = strrchr(mimic_argv[0], '/')) == NULL){
		mimic_short_name = mimic_argv[0];
	}else{
		mimic_short_name++;
	}

	if(envp){
		i = 0;
		while(envp[i]){
			if(!key_match(mimic_envp, envp[i])){
				if(!strncmp(envp[i], "_=", 2)){
					tmp_string_ptr = (char *) calloc(strlen(mimic_argv[0]) + 3, sizeof(char));
					tmp_string_ptr[0] = '_';
					tmp_string_ptr[1] = '=';
					memcpy(tmp_string_ptr + 2, mimic_argv[0], strlen(mimic_argv[0]));
					mimic_envp[mimic_envc++] = tmp_string_ptr;

				}else{
					mimic_envp[mimic_envc++] = envp[i];
				}
			}
			i++;
		}
	}


	printf("Launching child...");
	retval = fork();


	if(retval == -1){
		error(-1, errno, "fork()");

	}else if(retval){

		// parent
		child_pid = retval;
		printf("\t\t\tSuccess!\n");

		printf("Waiting for child to attach...");
		wait(NULL);
		printf("\t\tSuccess!\n");


		printf("Initializing ptrace_do...");
		if((child = ptrace_do_init(child_pid)) == NULL){
			fprintf(stderr, "ptrace_do_init(%d): %s\n", child_pid, strerror(errno));
			exit(-1);
		}
		printf("\t\tSuccess!\n");


		printf("Determining stack state...");
		errno = 0;
		peektext = ptrace(PTRACE_PEEKTEXT, child->pid, child->saved_regs.rsp, NULL);
		if(errno){
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT, %d, %lx, NULL): %s\n", \
					child->pid, (unsigned long) child->saved_regs.rsp, \
					strerror(errno));
			goto CLEAN_UP;
		}
		argc_stack_val = peektext;
		argv_stack_val = child->saved_regs.rsp + 0x8;
		envp_stack_val = argv_stack_val + ((argc_stack_val + 1) * 0x8);

		printf("\t\tSuccess!\n");


		// XXX add error checking here.
		printf("Politely requesting name change...");
		local_buffer = ptrace_do_malloc(child, strlen(mimic_short_name) + 1);
		memset(local_buffer, 0, strlen(mimic_short_name) + 1);
		memcpy(local_buffer, mimic_short_name, strlen(mimic_short_name));
		remote_buffer = ptrace_do_push_mem(child, local_buffer);

		errno = 0;
		ret_long = ptrace_do_syscall(child, __NR_prctl, PR_SET_NAME, (unsigned long) remote_buffer, 0, 0, 0, 0);
		if(errno){
			fprintf(stderr, "ptrace_do_syscall(%lx, __NR_prctl, PR_SET_NAME, %lx, 0, 0, 0, 0): %s\n", \
					(unsigned long) child, (unsigned long) remote_buffer, \
					strerror(errno));
			goto CLEAN_UP;
		}
		if(ret_long < 0){
			fprintf(stderr, "remote prctl(PR_SET_NAME, %lx, 0, 0, 0): %s\n", \
					(unsigned long) child->saved_regs.rsp + 0x8, \
					strerror(-ret_long));
			goto CLEAN_UP;
		}
		printf("\tSuccess!\n");


		printf("Searching for main()...");
		memcpy(&test_regs, &(child->saved_regs), sizeof(struct user_regs_struct));

		while(!((test_regs.rdi == argc_stack_val) && (test_regs.rsi == argv_stack_val) && (test_regs.rdx == envp_stack_val) && \
					(test_regs.rip > child->map_head->start_address) && (test_regs.rip <  child->map_head->end_address) && \
					(test_regs.rbp == 0) && (test_regs.rcx == 0) && (test_regs.rbx == 0))){

			if((ret_long = ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL)) == -1){
				fprintf(stderr, "ptrace(PTRACE_SINGLESTEP, %d, NULL, NULL): %s\n", \
						child->pid, \
						strerror(errno));
				break;
			}

			wait(&status);
			if(!WIFSTOPPED(status)){
				fprintf(stderr, "!WIFSTOPPED()\n");
				ret_long = -1;
				break;
			}

			if((ret_long = ptrace(PTRACE_GETREGS, child->pid, NULL, &test_regs)) == -1){
				fprintf(stderr, "ptrace(PTRACE_GETREGS, %d, NULL, %lx): %s\n", \
						child->pid, (unsigned long) &test_regs, \
						strerror(errno));
				break;
			}
		}

		if(ret_long == -1){
			fprintf(stderr, "Error: libc register setup not detected. Aborting!\n");
			goto CLEAN_UP;
		}
		printf("\t\t\tSuccess!\n");


		printf("Building execution headers...");
		memcpy(&(child->saved_regs), &test_regs, sizeof(struct user_regs_struct));

		//		execution_header_size = sizeof(unsigned long);
		execution_header_size = get_vector_byte_count(argv);
		execution_header_size += get_vector_byte_count(envp);
		execution_header_size += 2 * sizeof(unsigned long);

		if((execution_header_local = (char **) ptrace_do_malloc(child, execution_header_size)) == NULL){
			fprintf(stderr, "ptrace_do_malloc(%lx, %d): %s\n", \
					(unsigned long) child, (int) ((execute_argc * sizeof(char **)) + 1), \
					strerror(errno));
			goto CLEAN_UP;
		}
		memset(execution_header_local, 0, execution_header_size);

		if((execution_header_remote = ptrace_do_get_remote_addr(child, (void *) execution_header_local)) == NULL){
			fprintf(stderr, "ptrace_do_get_remote_addr(%lx, %lx): %s\n", \
					(unsigned long) child, (unsigned long) execution_header_local, \
					strerror(errno));
			goto CLEAN_UP;
		}

		build_execution_headers(execution_header_local, execution_header_remote, execute_argv, envp);

		if((execution_header_remote = ptrace_do_push_mem(child, execution_header_local)) == 0){
			fprintf(stderr, "ptrace_do_push_mem(%lx, %lx): %s\n", \
					(unsigned long) child, (unsigned long) execution_header_remote, \
					strerror(errno));
			goto CLEAN_UP;
		}

		ptrace_do_free(child, execution_header_local, FREE_LOCAL);
		printf("\t\tSuccess!\n");


		printf("Setting up state...");
		child->saved_regs.rdi = execute_argc;
		child->saved_regs.rsi = (unsigned long) execution_header_remote;
		child->saved_regs.rdx = (unsigned long) execution_header_remote + ((execute_argc + 1) * sizeof(char **));
		printf("\t\t\tSuccess!\n");

		printf("\n\tGood-bye and have a good luck! :)\n\n");

CLEAN_UP:
		ptrace_do_cleanup(child);

		if(!background){

			soh_string[0] = SOH_CHAR;
			soh_string[1] = NULL_CHAR;

			if((foreground_mimic_argv = (char **) calloc(mimic_argc + 3, sizeof(char **))) == NULL){
				fprintf(stderr, "calloc(%d, %d): %s\n", \
						tmp_size, (int) sizeof(char), strerror(errno));
				exit(-1);
			}

			i = 0;
			while(mimic_argv[i]){
				foreground_mimic_argv[i] = mimic_argv[i];
				i++;
			}
			foreground_mimic_argv[i++] = soh_string;
			foreground_mimic_argv[i] = mimic_short_name;

			execve(argv[0], foreground_mimic_argv, mimic_envp);
		}

		return(0);

	}else{

		//child
		if((retval = ptrace(PTRACE_TRACEME, 0, NULL, NULL)) == -1){
			error(-1, errno, "ptrace(PTRACE_TRACEME, 0, NULL, NULL)");
		}

		execve(execute_argv[0], mimic_argv, mimic_envp);
		error(-1, errno, "execve(%s, %lx, NULL)", execute_argv[0], (unsigned long) mimic_argv);
	}

	return(-1);
}



int key_match(char **vector, char *key_value){

	int i;
	char *ptr;

	i = 0;
	while(vector[i]){

		if((ptr = strchr(key_value, '=')) != NULL){
			if(!strncmp(vector[i], key_value, (int) (ptr - key_value) + 1)){
				return(1);
			}
		}

		i++;
	}

	return(0);
}



void build_execution_headers(void *local_buffer, void *base_addr, char **argv, char **envp){

	int i;
	int argc, envc;
	char **pointer_ptr;
	char *tmp_ptr_remote;
	char *tmp_ptr_local;
	int tmp_len;


	argc = 0;
	if(argv){
		while(argv[argc++]){}
	}

	envc = 0;
	if(envp){
		while(envp[envc++]){}
	}

	tmp_len = (argc * sizeof(char *)) + (envc * sizeof(char *)) + (2 * sizeof(char *));
	/*
		 printf("DEBUG: beh: tmp_len: %d\n", tmp_len);
		 printf("DEBUG: beh: local_buffer: %lx\n", (unsigned long) local_buffer);
		 printf("DEBUG: beh: base_addr: %lx\n", (unsigned long) base_addr);
		 printf("DEBUG: beh: argv: %lx\n", (unsigned long) argv);
		 printf("DEBUG: beh: envp: %lx\n", (unsigned long) envp);
	 */

	pointer_ptr = (char **) local_buffer;
	tmp_ptr_local = local_buffer + tmp_len;
	tmp_ptr_remote = base_addr + tmp_len;


	if(argv){	
		i = 0;
		while(argv[i]){
			*(pointer_ptr++) = tmp_ptr_remote;
			tmp_len = strlen(argv[i]);
			memcpy(tmp_ptr_local, argv[i], tmp_len);
			tmp_ptr_local += tmp_len + 1;
			tmp_ptr_remote += tmp_len + 1;

			i++;
		}

		pointer_ptr++;
	}	

	if(envp){	
		i = 0;
		while(envp[i]){
			*(pointer_ptr++) = tmp_ptr_remote;
			tmp_len = strlen(envp[i]);
			memcpy(tmp_ptr_local, envp[i], tmp_len);
			tmp_ptr_local += tmp_len + 1;
			tmp_ptr_remote += tmp_len + 1;

			i++;
		}
	}	
}



int get_vector_byte_count(char **argv){

	int i = 0;
	int total_strlen = 0;

	while(argv[i]){
		total_strlen += strlen(argv[i]);
		i++;
	}

	return( ((i + 1) * sizeof(void *)) + total_strlen + (i * sizeof(char)) );
}


