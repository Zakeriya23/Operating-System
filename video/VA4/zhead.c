#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libgen.h>

int main(int argc, char * argv[]) {

    char * lines = NULL;
    char * file_name =  NULL;
    
    {
        int c = 0;
        while((c = getopt(argc, argv, "hn:")) != -1) {
            switch(c) {
                case 'n':
                    lines = optarg;
                    break;
                case 'h':
                    printf("emacs is best!!!\n");
                    exit(EXIT_SUCCESS);
                    break;
                default: 
                    break;
            }
        }
    
        if(optind < argc) {
            file_name = argv[optind];
        }
        else {
            fprintf(stderr, "Missing file name\n");
            exit(EXIT_SUCCESS);
        }

        {
            int pipes[2] = {-1, -1};
            pid_t pid = -1;

            pipe(pipes);
            pid = fork();
            switch (pid) {
                case -1:
                    perror("fork failed");
                    return EXIT_FAILURE;
                    break;
                case 0:
                {
                    char **rhp_argv = NULL;
                    char rhp[] = "head";
                    if (dup2(pipes[STDIN_FILENO], STDIN_FILENO) < 0) {
                        perror("child process failed dup2");
                        _exit(EXIT_FAILURE);
                    }
                    close(pipes[STDIN_FILENO]);
                    close(pipes[STDOUT_FILENO]);
                    if (NULL != lines) {
                        rhp_argv = (char **) calloc(4, sizeof(char *));
                        rhp_argv[0] = rhp;
                        rhp_argv[1] = strdup("-n");
                        rhp_argv[2] = lines;
                    }
                    else {
                        rhp_argv = (char **) calloc(2, sizeof(char*));
                        rhp_argv[0] = rhp;
                    }
                    execvp(rhp_argv[0], rhp_argv);
                    perror("child failed exec");
                    fprintf(stderr, "*** %d: %s failed ***\n", getpid(), rhp);
                    fflush(stderr);
                    _exit(EXIT_FAILURE);
                }
                break;
                
                default:
                {
                    char *lhp_argv[] = {
                        "zcat",
                        file_name,
                        (char *) NULL
                    };

                    if (dup2(pipes[STDOUT_FILENO], STDOUT_FILENO) < 0) {
                        perror("zhead 2 failed dup2");
                        return(EXIT_FAILURE);
                    }
                    close(pipes[STDIN_FILENO]);
                    close(pipes[STDOUT_FILENO]);
                    execvp(lhp_argv[0], lhp_argv);

                    perror("parent failed exec");
                    fprintf(stderr, "*** %d: zcat parent failed ***\n", getpid());
                    exit(EXIT_FAILURE);
                }
                break;
            }
        }
    }
    return EXIT_SUCCESS;
}