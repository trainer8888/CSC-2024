#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    FILE *f = fopen("secret_answer.txt", "wb");
    srand(time(0));
    char secret[0x10];
    for (int i = 0; i < 0x10; i++)
    {
        secret[i] = 48 + (rand() % (126 - 47) + 1);
    }
    fwrite(secret, 1, 0x10, f);
    fclose(f);
    return 0;
}