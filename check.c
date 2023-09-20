// C program to convert
// Hexadecimal number to Binary
 
#include <stdio.h>
#include <String.h>
#include <stdlib.h>
#include <math.h>

int main() {
    FILE* file;
    file = fopen("thisisatest.txt", "w");
     if (file == NULL) {
        printf("The file is not opened. The program will "
               "now exit.");
        exit(0);
    }
    int a = 10;
    fprintf(file, "%s %d","We are enjoying our times", a);
    FILE* x;
    fopen("what.txt", "w");
    if (x == NULL) {
        printf("The file is not opened. The program will "
               "now exit.");
        exit(0);
    }

}