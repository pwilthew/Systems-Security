#include <stdio.h>
#include <time.h>

FILE *scorefile;
int get_score(char *name, char *ssn, char *score);
char* str_prefix(char *prefix, char *str);

int main(int argc, char *argv[])
{
	int ruid, euid;
	char score[128];

	if (argc != 3) {
		printf("Usage: getscore name SSN\n");
		exit(1);
	}

	time_t current_time = time(NULL);

	ruid = getuid ();
	euid = geteuid ();
	// This is to make sure the logging command will have
	// sufficient privilege.
	if (setreuid(euid, euid)){
		perror("setreuid");
	}

	scorefile = fopen("score.txt", "r");
	if (scorefile == NULL){
		printf ("failed to open score file\n");
	}
	else{
		if (get_score(argv[1], argv[2], score)){
			char command[256];
			printf("Invalid user name or SSN.\n");
			sprintf(command, "echo \"%s: Invalid user name or SSN: %s,%s\"|cat >> error.log", 
					ctime(&current_time), argv[1], argv[2]);
		 	if (system(command)){
				perror("Logging");
			}
			exit(-1);
		}
		printf("Your score is %s\n", score);
	}
}

int get_score(char *name, char *ssn, char *score)
{
	char matching_pattern[128];
	char line[128];
	char *match_point; 

	strcpy(matching_pattern, name);
	strcat(matching_pattern, ":");
	strcat(matching_pattern, ssn);

	while (fgets(line, 128, scorefile)!=NULL){
		if (match_point=str_prefix(matching_pattern, line)){
			if (*match_point++==':'){
				while (*match_point!=':'){
					*score++=*match_point++;
				}
				*score=0;
				return 0;
			}
		}
	}

	return -1;
}

char* str_prefix(char *prefix, char *str){
	while (*prefix && *str){
		if (*prefix != *str)
			return NULL;
		prefix++;
		str++;
	}
	return *prefix==0?str:NULL;
}

