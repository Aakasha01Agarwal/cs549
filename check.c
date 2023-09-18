// C program to convert
// Hexadecimal number to Binary
 
#include <stdio.h>
#include <String.h>
#include <stdlib.h>
// function to convert Hexadecimal to Binary Number

int* decimalToBinary(int decimal, int* binarySize) {
    int i;

    // Calculate the number of bits required for the binary representation
    int temp = decimal;
    int numBits = 0;
    while (temp > 0) {
        temp /= 2;
        numBits++;
    }

    // Ensure a minimum of 12 bits
    if (numBits < 12) {
        numBits = 12;
    }

    // Create the binary array dynamically
    int* binaryArray = (int*)malloc(numBits * sizeof(int));
    if (binaryArray == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }

    // Initialize the binary array to all zeros
    for (i = 0; i < numBits; i++) {
        binaryArray[i] = 0;
    }

    // Convert decimal to binary
    for (i = numBits - 1; i >= 0 && decimal > 0; i--) {
        binaryArray[i] = decimal % 2;
        decimal /= 2;
    }

    *binarySize = numBits;
    return binaryArray;
}

// driver code
int main()
{
 
    int decimal = 80;
    // printf("Enter a decimal number: ");
    // scanf("%d", &decimal);

   int binarySize;
    int* binaryResult = decimalToBinary(decimal, &binarySize);

    printf("Binary representation: ");
    for (int i = 0; i < binarySize; i++) {
        printf("%d", binaryResult[i]);
    }
    printf("\n");

}