#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h> 

static int verbose = 0;

#define VERBOSE(...)                  \
    do { if (verbose) printf(__VA_ARGS__); } while (0)

typedef struct {
	char *dir_name;
	char *file_name;
} args_t;


args_t parse_dir_arg(int argc, char *argv[]);
void null_opendir_pointer_error_handling(const char *directory_name);
void rename_file(const char *name, const char *dir_name);

int main(int argc, char *argv[]) {
		
	args_t args = parse_dir_arg(argc, argv);

	if (args.file_name != NULL){
		if (strchr(args.file_name, ' ' ) == NULL){
			VERBOSE("File '%s' does not contain space in name. Doing nothing.\n", args.file_name);
			return EXIT_FAILURE;
		}
		else
			rename_file(args.file_name, ".");
	}
	else{
		
		char *dir_name = args.dir_name;

		struct dirent *entry;
		DIR *dp = opendir(dir_name);

		if (dp == NULL){
			null_opendir_pointer_error_handling(dir_name);
			return EXIT_FAILURE;
		}
		

		while ((entry = readdir(dp)) != NULL){
			char *name = entry->d_name;
			if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
				continue;
			
			else if (strchr(name, ' ') == NULL){
				VERBOSE("Discrarding the file '%s' since it does not contain spaces.\n", name);
				continue;
			}

			rename_file(name, dir_name);
			
		}
	
		closedir(dp);
	}
	return EXIT_SUCCESS;
}



args_t parse_dir_arg(int argc, char *argv[]){
	args_t args = {.dir_name = NULL, .file_name = NULL};
	
	static struct option long_options[] = {
		{"dir",	 required_argument, NULL, 'd'},
		{ "verbose", no_argument, NULL, 'v' },
		{0, 0, NULL, 0}
	};

	int opt, option_index = 0;

	while ((opt = getopt_long(argc, argv, "d:v:", long_options, &option_index)) != -1){
		switch (opt){
			case 'd':
				args.dir_name = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
			default:
				fprintf(stderr, "Usge: %s [--dir <directory>]\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind < argc){
		args.file_name = argv[optind++];
		args.dir_name = NULL;
	}

	if (args.dir_name == NULL && args.file_name == NULL){
		fprintf(stderr, "Error: you must specify either -d/--dir <directory> or a filename.\n"
				"Usage: %s [-v|--verbose][-d|--dir <directory>] [filename]\n", argv[0]
				);
		exit(EXIT_FAILURE);
	}

	return args;
}




void null_opendir_pointer_error_handling(const char *directory_name){
	switch (errno){
		case ENOENT:
			fprintf(stderr, "Error: directory \"%s\" does not exist.\n", directory_name);
                        break;
		case ENOTDIR:
			fprintf(stderr, "Error: \"%s\" is not a directory\n.", directory_name);
                        break;
		case EACCES:
			fprintf(stderr, "Error: permission denied opening \"%s\".\n", directory_name);
			break;
		default:
			fprintf(stderr, "Error opening \"%s\": %s\n", directory_name, strerror(errno));
	}
}


void rename_file(const char *name, const char *dir_name){
	size_t len = strlen(name);
	char *newname = malloc(len+1);
        if (newname == NULL){
		fprintf(stderr, "Put of memory when renaiming '%s'.\n", name);
		return;
	}
    	VERBOSE("Considering the file '%s' - updating it's name.\n", name);
        for (size_t i = 0; i < len; i++){
		newname[i] = (name[i] == ' ') ? '_': name[i];
	}
	newname[len] = '\0';
	VERBOSE("\nNew filename: %s\n", newname);

	char oldpath[PATH_MAX];
    char newpath[PATH_MAX];
    // note: snprintf will NUL-terminate as long as PATH_MAX > needed
    snprintf(oldpath, sizeof oldpath, "%s/%s", dir_name, name);
    snprintf(newpath, sizeof newpath, "%s/%s", dir_name, newname);
	
	if (rename(oldpath, newpath) != 0){
		VERBOSE("Failed renaiming file from '%s' to '%s'.\n", name, newname);
		}
    else {
		VERBOSE("Renamed the file from '%s' to '%s'.\n", name, newname);
	}
	free(newname);
}