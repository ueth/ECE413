#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#define FAIL -1

bool file_exists(const char*);
int bytes_added( int result_of_sprintf );
void export_log(int fileno, int access_type, int action_denied,const char *file_name);
char *get_file_hash(int fileno);

bool file_exists(const char *filename) {
	struct stat buffer;   
	return (stat (filename, &buffer) == 0);
}

int bytes_added( int result_of_sprintf ){
    return (result_of_sprintf > 0) ? result_of_sprintf : 0;
}

char *get_file_hash(int fileno){
	/*Generate hash*/
	MD5_CTX mdContext;
	int bytes = 0;
    unsigned char data[256];
	unsigned char c[MD5_DIGEST_LENGTH];
	char *file_hash = malloc(MD5_DIGEST_LENGTH * sizeof(char) * 2);

	if(fileno == -1){
		file_hash = "NULL";
	}
	else{
		MD5_Init(&mdContext);
		bytes = read(fileno, data, 256);

		if (bytes > 0){
			while(bytes > 0){
				MD5_Update(&mdContext, data, bytes);
				bytes = read(fileno, data, 256);
			}  
			MD5_Final (c, &mdContext);
		}
		else if(bytes == 0){
			/* empty file */
			MD5_Update(&mdContext, data, bytes);
			MD5_Final(c, &mdContext);           
		}
		
		int length = 0;

		for(int i = 0; i < MD5_DIGEST_LENGTH; i++) 
			length +=  bytes_added(sprintf(file_hash + length, "%02x", c[i]));
	}
	
	return file_hash;
}

void export_log(int fileno, int access_type, int action_denied,const char *file_name){
	char line[512];

	/*Get user's ID*/
	uid_t uid = getuid();

	/*Get time*/
	time_t t; 
	struct tm *time_info;
	time(&t);
	time_info = localtime(&t);

	char *file_hash = get_file_hash(fileno);

	/*Use open instead of fopen*/
	int fd = open("file_logging.log", O_WRONLY | O_APPEND);

	/*Generate log line*/
	sprintf(line,"%d %s %d-%d-%d %d:%d:%d %d %d %s\n", uid, file_name, time_info->tm_mday, time_info->tm_mon, time_info->tm_year+1900, 
	time_info->tm_hour, time_info->tm_min, time_info->tm_sec, access_type, action_denied, file_hash);

	write(fd, line, strlen(line));

	close(fd);
}

FILE *fopen(const char *path, const char *mode) {
	printf("Calling fopen for file -> %s\n", path);
	int action_denied = 0, access_type = 0, fd;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	access_type = file_exists(path) ? 1 : 0;

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	action_denied = (!original_fopen_ret) ? 1 : 0;
	fd = action_denied ? -1 : fileno(original_fopen_ret);

	char result[1024];

	/*Can't get full path of a file that we can't access*/
	if(fd != -1){
		char path2[1024];
		sprintf(path2, "/proc/self/fd/%d", fileno(original_fopen_ret));
		memset(result, 0, sizeof(result));
		readlink(path2, result, sizeof(result)-1);
	}

	/*We dont want to keep logs for these files*/
	if((strcmp(path, "file_logging.log") == 0) || (strcmp(path, "file_logging_encrypted.log") == 0) || (strcmp(path, "public.key") == 0) || (strcmp(path, "file_logging_decrypted") == 0))
		return original_fopen_ret;
		
	export_log(fd, access_type, action_denied, (fd == -1) ? path : result);

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	int action_denied = 0, access_type = 0;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	action_denied = (original_fwrite_ret < size) ? 1 : 0;

	access_type = ((ptr == NULL) || (size == 0)) ? 3 : 2;

	/*Generate full path*/
	char path[1024];
	char result[1024];
	sprintf(path, "/proc/self/fd/%d", fileno(stream));
	memset(result, 0, sizeof(result));
	readlink(path, result, sizeof(result)-1);

	/*We dont want to keep logs for these files*/
	if((strstr(result, "file_logging_encrypted.log") != NULL))
		return original_fwrite_ret;

	printf("Calling fwrite \n");
	
	export_log(fileno(stream), access_type, action_denied, result);

	return original_fwrite_ret;
}