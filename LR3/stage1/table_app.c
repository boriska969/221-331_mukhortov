/* table_app.c
 * ЛР3, этап 1: незащищённое консольное приложение с табличным хранилищем.
 * Номер строки передаётся в командной строке. Если строки с таким номером нет,
 * выводится предупреждение. Эта версия используется как эталон для проверки
 * версии, которая работает внутри анклава (этапы 2-3).
 *
 * Использование: table_app <номер строки>
 */
#include <stdio.h>
#include <stdlib.h>

/* Имитация защищаемого хранилища: учётные записи в виде строк "логин;пароль".
 * Записи выдуманные. */
static const char* const kTable[] = {
    "alice.morgan;Vq7#mLx2!tRp",
    "bkaramov;Krt9$wYe4@Lzn",
    "night_owl_77;Plm3&zQe8?Vna",
    "j.petrova;Hd5*nRt2%Woq",
    "dev-team-01;Zx8!cVb4#Mkl",
};

#define TABLE_ROWS ((int)(sizeof kTable / sizeof kTable[0]))

/* Печатает строку таблицы с номером row (нумерация с нуля).
 * Возвращает 0, если строка найдена, иначе -1 (с предупреждением). */
static int print_row(int row)
{
    if (row < 0 || row >= TABLE_ROWS) {
        printf("WARNING: row %d does not exist (table has %d rows)\n", row, TABLE_ROWS);
        return -1;
    }
    printf("row %d: %s\n", row, kTable[row]);
    return 0;
}

/* Точка входа. Возвращает 0 при успешной печати строки, 1 - при ошибке аргументов или
 * отсутствии строки. */
int main(int argc, char* argv[])
{
    char* end = NULL;
    long row;

    if (argc != 2) {
        printf("usage: table_app <row number>\n");
        return 1;
    }
    row = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0') {
        printf("WARNING: '%s' is not a row number\n", argv[1]);
        return 1;
    }
    return print_row((int)row) == 0 ? 0 : 1;
}
