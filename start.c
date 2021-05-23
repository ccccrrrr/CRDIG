#include <stdio.h>
#include "copy.c"
#include <unistd.h>
extern char *optarg;  //选项的参数指针
extern int optind;   //下一次调用getopt的时，从optind存储的位置处重新开始检查选项。 
extern int opterr;  //当opterr=0时，getopt不向stderr输出错误信息。
extern int optopt;  //当命令行选项字符不包括

void hasServerGetHostByName(char* selectServer, char* hostname) {
    ngethostbyname(hostname, selectServer, 1);
    return;
}

int main(int argc, char *argv[]) {

    int errors;
    char c;
    char target[20] = {0};
    printf("argc: %d\n", argc);
    if(argc > 1) {
        strcpy(target, argv[1]);
    }else {
        printf("error input, please check your input...");
        return 0;
    }
    if(argc > 2) {
        while ((c = getopt(argc, argv, "s:t")) != -1) {
            switch (c) {
                case 's': /* @server */
                    hasServerGetHostByName(optarg, target);
                    // printf("s: %s\n", optarg);
                    break;
                case 't': /* trace */
                    printf("t\n");
                    ngethostbyname_trace(target, "", 1);
                    break;
                default:
                    ngethostbyname(target, "", 1);
                    printf("default %s\n", optarg);
                    break;            
            }
        }
    } else {
        printf("target: %s\n", target);
        /* default server */
        ngethostbyname(target, "", 1);
    }
}