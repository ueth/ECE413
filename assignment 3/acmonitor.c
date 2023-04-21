#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry *read_log_file(FILE *fp);
struct entry *add_element(struct entry *head, int uid, char *file_name, char *date, char *time, int access_type, int action_denied, char *fingerprint);
void print_unauthorized_users(struct entry *head);
void print_file_edits(struct entry *head, char *file_to_scan);

struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */
	char *date; /* file access date */
	char *time; /* file access time */
	char *file_name; /* filename (string) */
	char *fingerprint; /* file fingerprint */
	struct entry *next; /*pointer for linked list*/
};

struct un_user{
	int uid;
	int count;
	struct un_user *next;
};


void usage(void){
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void list_unauthorized_accesses(FILE *log){
	struct entry *head = read_log_file(log);
	print_unauthorized_users(head);
}


void list_file_modifications(FILE *log, char *file_to_scan){
	struct entry *head = read_log_file(log);
	print_file_edits(head, file_to_scan);
}


int main(int argc, char *argv[]){

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	/*Decryption happens here and then we use the decrypted file*/
	decrypt("file_logging_encrypted.log", "file_logging_decrypted.log", "private.key");

	/*use the decrypted file*/
	log = fopen("file_logging_decrypted.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}

struct entry *read_log_file(FILE *fp){
	struct entry *head = NULL;
	char * line = NULL;
    size_t len = 0;
    ssize_t read;

	if (fp == NULL)
        exit(EXIT_FAILURE);

	while((read = getline(&line, &len, fp)) != -1){
		char *str[7];

		char *st = strtok(line, " ");
		
		int counter = 0;

		while(st != NULL){
			str[counter] = st;
			st = strtok(NULL, " ");
			counter++;
		}

		head = add_element(head, atoi(str[0]), str[1], str[2], str[3], atoi(str[4]), atoi(str[5]), str[6]);
	}

	if(line) free(line);

	return head;
}

struct entry *add_element(struct entry *head, int uid, char *file_name, char *date, char *time, int access_type, int action_denied, char *fingerprint){
	struct entry *node = (struct entry *)malloc(sizeof(struct entry));
	struct entry *current = head;

	node->uid = uid;

	node->file_name = (char *)malloc(strlen(file_name) * sizeof(char));
	strcpy(node->file_name, file_name);

	node->date = (char *)malloc(strlen(date) * sizeof(char));
	strcpy(node->date, date);

	node->time = (char *)malloc(strlen(time) * sizeof(char));
	strcpy(node->time, time);

	node->access_type = access_type;
	node->action_denied = action_denied;

	node->fingerprint = (char *)malloc(strlen(fingerprint) * sizeof(char));
	strcpy(node->fingerprint, fingerprint);

	node->next = NULL;

	if(head == NULL) return node;

	while(current->next != NULL) current = current->next;

	current->next = node;

	return head;
}

void print_unauthorized_users(struct entry *head){
	int max_count = 7;
	struct entry *current = head;
	struct un_user *user = NULL;

	while(current != NULL){
		if(current->action_denied == 1){
			
			if(user == NULL){
				user = (struct un_user *)malloc(sizeof(struct un_user));
				user->uid = current->uid;
				user->count++;
				user->next = NULL;
			}
			else{	
				struct un_user *current_user = user;

				while((current_user != NULL) && (current_user->uid != current->uid))
					current_user = current_user->next; 
					
				if(current_user == NULL){
					current_user = (struct un_user *)malloc(sizeof(struct un_user));
					current_user->uid = current->uid;
					current_user->count++;
					current_user->next = user;
					user = current_user;
				}
				else{
					current_user->count++;
				}
			}
		}
		current = current->next;
	}

	int uncounter = 0;

	while(user){
		if(user->count >= 7){
			printf("User with id: %d has been found to have unauthorized access\n", user->uid);
			uncounter++;
		}
		user = user->next;
	}

	if(uncounter == 0) printf("No unauthorized users were found\n");
}

void print_file_edits(struct entry *head, char *file_to_scan){
	struct entry *current = head;
	struct un_user *user = NULL;

	while(current != NULL){
		/*Check if the given name matches with the current one*/ /*If the access type is 2 or 3 we have write or delete = modified*/
		if((strstr(current->file_name, file_to_scan) != NULL) && ((current->access_type == 2) || (current->access_type == 3))){
			
			if(user == NULL){
				user = (struct un_user *)malloc(sizeof(struct un_user));
				user->uid = current->uid;
				user->count++;
				user->next = NULL;
			}
			else{	
				struct un_user *current_user = user;

				while((current_user != NULL) && (current_user->uid != current->uid))
					current_user = current_user->next; 
					
				if(current_user == NULL){
					current_user = (struct un_user *)malloc(sizeof(struct un_user));
					current_user->uid = current->uid;
					current_user->count++;
					current_user->next = user;
					user = current_user;
				}
				else{
					current_user->count++;
				}
			}
		}
		current = current->next;
	}
	int uncounter = 0;

	while(user){
		printf("User with id: %d has modified %s %d times.\n", user->uid, file_to_scan, user->count);
		uncounter++;
		user = user->next;
	}

	if(uncounter == 0) printf("No user modified this file.\n");
}