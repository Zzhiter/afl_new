// #include <stdio.h>
// #include <stdlib.h>
// #include "ok_jpg.h"
// #include "ok_jpg.c"
 
// int main(int _argc, char **_argv) {
//     //把第一个参数当作文件名，这个名就是个相对路径，不过在fuzz的时候可以用@@来代替
//     FILE *file = fopen(_argv[1], "rb");
//     //读取jpg格式图片
//     ok_jpg image = ok_jpg_read(file, OK_JPG_COLOR_FORMAT_RGBA);
//     fclose(file);
//     if (image.data) {
//         printf("Got image! Size: %li x %li\n", (long)image.width, (long)image.height);
//         free(image.data);
//     }
//     return 0;
// }

#include <stdio.h>
#include <stdlib.h>
#include "ok_jpg.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.jpg>\n", argv[0]);
        return 1;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
        return 1;
    }
    ok_jpg image = ok_jpg_read(file, OK_JPG_COLOR_FORMAT_RGBA);
    fclose(file);
    if (image.data) {
        printf("Got image! Size: %li x %li\n", (long)image.width, (long)image.height);
        free(image.data);
    }
    return 0;
}
