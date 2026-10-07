#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static const char* const kTable[] = {
    "alice.morgan;Vq7#mLx2!tRp",
    "bkaramov;Krt9$wYe4@Lzn",
    "night_owl_77;Plm3&zQe8?Vna",
    "j.petrova;Hd5*nRt2%Woq",
    "dev-team-01;Zx8!cVb4#Mkl",
};

#define TABLE_ROWS ((int)(sizeof kTable / sizeof kTable[0]))

static int print_row(int row)
{
    if (row < 0 || row >= TABLE_ROWS) {
        printf("WARNING: row %d does not exist (table has %d rows)\n", row, TABLE_ROWS);
        return -1;
    }
    printf("row %d: %s\n", row, kTable[row]);
    return 0;
}

int main(int argc, char* argv[])
{
    char* end = NULL;
    long row;

    if (argc != 2) {
        printf("usage: table_app <row number>\n");
        return 1;
    }
    errno = 0;
    row = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || errno == ERANGE || row < INT_MIN || row > INT_MAX) {
        printf("WARNING: '%s' is not a row number\n", argv[1]);
        return 1;
    }
    return print_row((int)row) == 0 ? 0 : 1;
}
