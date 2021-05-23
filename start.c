#include <stdio.h>
#include "copy.c"
#include <unistd.h>
extern char *optarg;  //选项的参数指针
extern int optind;   //下一次调用getopt的时，从optind存储的位置处重新开始检查选项。 
extern int opterr;  //当opterr=0时，getopt不向stderr输出错误信息。
extern int optopt;  //当命令行选项字符不包括

void myGetHostByName(char* selectServer, char* hostname, int trace_or_not, int select_or_not) {
    if(trace_or_not == 0 && select_or_not == 0) {
        ngethostbyname(hostname, "", T_A);
    }else if(trace_or_not * select_or_not == 1) {
        ngethostbyname_trace(hostname, selectServer, 1);
    }else if(trace_or_not == 1) {
        ngethostbyname_trace(hostname, "", 1);
    }else if(select_or_not == 1) {
        ngethostbyname(hostname, selectServer, 1);
    }
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
        int trace_or_not = 0;
        int select_or_not = 0;
        char selectServer[20] = {0};
        while ((c = getopt(argc, argv, "s:t")) != -1) {
            switch (c) {
                case 's': /* @server */
                    select_or_not = 1;
                    strcpy(selectServer, optarg);
                    break;
                case 't': /* trace */
                    trace_or_not = 1;
                    break;
                default:
                    // ngethostbyname(target, "", 1);
                    printf("default %s\n", optarg);
                    break;            
            }
        }
        myGetHostByName(selectServer, target, trace_or_not, select_or_not);
    } else {
        printf("target: %s\n", target);
        /* default dns search */
        ngethostbyname(target, "", 1);
    }
}