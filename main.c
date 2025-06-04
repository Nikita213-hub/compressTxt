#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_api.h"

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTION] FILE\n", program_name);
    printf("Options:\n");
    printf("  -c    Compress FILE\n");
    printf("  -d    Decompress FILE\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *option = argv[1];
    const char *input_filename = argv[2];
    char *output_filename;
    int result;

    if (strcmp(option, "-c") == 0) {
        // Compression
        output_filename = generate_output_filename(input_filename, ".bin");
        if (!output_filename) {
            printf("Error generating output filename\n");
            return 1;
        }
        result = compress_file(input_filename, output_filename);
        free(output_filename);
        return result;
    } else if (strcmp(option, "-d") == 0) {
        // Decompression
        output_filename = generate_output_filename(input_filename, ".txt");
        if (!output_filename) {
            printf("Error generating output filename\n");
            return 1;
        }
        result = decompress_file(input_filename, output_filename);
        free(output_filename);
        return result;
    } else {
        print_usage(argv[0]);
        return 1;
    }
}