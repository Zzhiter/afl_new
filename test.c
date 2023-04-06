#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <signal.h> 

#define MAX_LEN 1000

int a[10];

void foo(int i) {
    a[i] = -1;
    // printf("%d\n", a[1]);
}

int vuln(char *str)
{
    int len = strlen(str);
    if(str[0] == 'A' && len == 66)
    {
        raise(SIGSEGV);
        //如果输入的字符串的首字符为A并且长度为66，则异常退出
    }
    else if(str[0] == 'F' && len == 6)
    {
        raise(SIGSEGV);
        //如果输入的字符串的首字符为F并且长度为6，则异常退出
    }
    else
    {
        printf("it is good!\n");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    // char buf[100]={0};
    // gets(buf);//存在栈溢出漏洞
    
    char str[MAX_LEN];
    int len;

    fgets(str, MAX_LEN, stdin);

    foo(strlen(str));

    vuln(str);

    return 0;
}

// #include <stdio.h>
// int func2()
// {
//     int a,b =1;
//     return a+b;
// }
// int func1()
// {
//     int a,b =1;
//     func2();
//     return a+b;
// }
// int main()
// {
//     func1();
//     int a[10] = {0};
//     printf("%d\n", a[5]);
    
//     return 0;
// }

// #include <stdio.h>

// int a[10];

// void foo(int i) {
//     a[i] = -1;
//     // printf("%d\n", a[1]);
// }

// int main() {
//     foo(5);

//     for (int i = 0; i < 9; i ++) {
//         foo(i);
//     }

//     gets()

//     // printf("%d\n", a[5]);
//     // printf("%d\n", a[0]);
// }
