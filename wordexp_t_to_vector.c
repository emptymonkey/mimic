
#define _GNU_SOURCE


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>


/***********************************************************************************************************************
 *
 *	wordexp_t_to_vector()
 *
 *		Input: A pointer to a wordexp_t struct. These are generally created by the wordexp() funtion provided by glibc.
 *		Output: A vector containing the same data. 
 *
 *		Purpose: Once a command line entry has been parsed by wordexp(), it may still be useful to have it back in 
 *			vector form. This function helps that.
 *
 **********************************************************************************************************************/
char **wordexp_t_to_vector(wordexp_t *wordexp_t_in){

  unsigned int i;
  int string_len;
  char **vector;


  if((vector = (char **) calloc(wordexp_t_in->we_wordc + 1, sizeof(char *))) == NULL){
    fprintf(stderr, "%s: wordexp_t_to_vector(): calloc(%d, %d): %s\n",
        program_invocation_short_name, \
        (int) wordexp_t_in->we_wordc + 1, (int) sizeof(char *), \
        strerror(errno));
    return(NULL);
  }

  for(i = 0; i < wordexp_t_in->we_wordc; i++){
    string_len = strlen(wordexp_t_in->we_wordv[i]);
    if((vector[i] = (char *) calloc(string_len + 1, sizeof(char))) == NULL){
      fprintf(stderr, "%s: wordexp_t_to_vector(): calloc(%d, %d): %s\n",
          program_invocation_short_name, \
          string_len + 1, (int) sizeof(char), \
          strerror(errno));
      goto CLEAN_UP;
    }

    memcpy(vector[i], wordexp_t_in->we_wordv[i], string_len + 1);
  }

  return(vector);

CLEAN_UP:

  i = 0;
  while(vector[i]){
    free(vector[i]);
  }
  free(vector);

  return(NULL);
}

