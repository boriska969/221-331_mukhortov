#include <stdio.h>
#include <string.h>

#define LR2_FILE_SIZE 256

static int read_fixed(const char* path, char* buffer)
{
    FILE* file = NULL;
    size_t bytesRead = 0;

    if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    bytesRead = fread_s(buffer, LR2_FILE_SIZE, 1, LR2_FILE_SIZE, file);
    fclose(file);
    return (int)bytesRead;
}

static int write_fixed(const char* path, const char* text)
{
    char buffer[LR2_FILE_SIZE];
    size_t length = strlen(text);
    FILE* file = NULL;

    if (length > LR2_FILE_SIZE) {
        length = LR2_FILE_SIZE;
    }
    memset(buffer, ' ', sizeof buffer);
    memcpy(buffer, text, length);
    if (fopen_s(&file, path, "wb") != 0 || file == NULL) {
        return -1;
    }
    fwrite(buffer, 1, LR2_FILE_SIZE, file);
    fclose(file);
    return 0;
}

static void show_file(const char* title, const char* path)
{
    char buffer[LR2_FILE_SIZE];
    int bytes = read_fixed(path, buffer);
    int index;

    printf("%s (%s):\n", title, path);
    if (bytes < 0) {
        printf("  cannot read file\n");
        return;
    }
    printf("  ");
    for (index = 0; index < bytes; ++index) {
        unsigned char symbol = (unsigned char)buffer[index];
        putchar((symbol >= 0x20u && symbol < 0x7fu) ? (char)symbol : '.');
    }
    printf("\n  bytes read: %d\n", bytes);
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        printf("usage: lab2_client show|write|demo <file> [text]\n");
        return 1;
    }
    if (strcmp(argv[1], "show") == 0) {
        show_file("file content", argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "write") == 0 && argc >= 4) {
        if (write_fixed(argv[2], argv[3]) != 0) {
            printf("cannot write file\n");
            return 1;
        }
        printf("written %d bytes to %s\n", LR2_FILE_SIZE, argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "demo") == 0) {
        show_file("1) content before modification", argv[2]);
        if (write_fixed(argv[2], "Secret text written by lab2_client") != 0) {
            printf("cannot write file\n");
            return 1;
        }
        show_file("2) content after write", argv[2]);
        return 0;
    }
    printf("usage: lab2_client show|write|demo <file> [text]\n");
    return 1;
}
