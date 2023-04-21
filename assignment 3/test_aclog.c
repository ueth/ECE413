#include <stdio.h>
#include <string.h>

extern void encrypt(char *input_path, char *output_path, char *key_path);

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	printf("-----------Calling fopen() for noacc.txt-----------\n");

	//Removed all rights of noacc file with chmod 000
	//For no rights files you have to provide the full path of the file.
	for(int i=0; i<8; i++){
		file = fopen("/home/alekos/Desktop/gitfolder/ECE-413/assign_3/noacc.txt", "r+");

		if(file == NULL) printf("fopen failed!\n");
		else printf("fopen succeded.\n");
	}

	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], 1, strlen(filenames[i]), file);
			fclose(file);
		}

	}

	printf("-----------Calling fopen() for test1.txt-----------\n");

	file = fopen("test1.txt", "w");

	if(file == NULL) printf("fopen failed!\n");
	else printf("fopen succeded.\n");

	fwrite("asdf", 1, 4, file);
	fwrite("1234", 1, 4, file);
	fwrite("qwer", 1, 4, file);

	fclose(file);

	file = fopen("test1.txt", "w");

	if(file == NULL) printf("fopen failed!\n");
	else printf("fopen succeded.\n");

	/*This should be action 3 (Delete-File)*/
	fwrite("", 0, 0, file);

	fclose(file);

	/*Encryption happens here, every fopen and fwrite must be above this*/
	encrypt("file_logging.log", "file_logging_encrypted.log", "public.key");
}
