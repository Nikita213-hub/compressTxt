#ifndef FILE_API_H
#define FILE_API_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include "huffman.h"

#define MAX_FILENAME_LEN 256
#define MAX_BUFFER_SIZE 4096

// Function to generate output filename based on input filename
char* generate_output_filename(const char *input_filename, const char *new_extension) {
    char *output_filename = (char*)malloc(MAX_FILENAME_LEN);
    if (!output_filename) return NULL;

    // Copy input filename
    strncpy(output_filename, input_filename, MAX_FILENAME_LEN - 1);
    output_filename[MAX_FILENAME_LEN - 1] = '\0';

    // Find the last dot
    char *last_dot = strrchr(output_filename, '.');
    if (last_dot) {
        // Remove everything after and including the last dot
        *last_dot = '\0';
    }

    // Add new extension
    strncat(output_filename, new_extension, MAX_FILENAME_LEN - strlen(output_filename) - 1);
    return output_filename;
}

// Function to add .txt extension if not present
void ensure_txt_extension(char *filename) {
    if (strlen(filename) < 4 || strcmp(filename + strlen(filename) - 4, ".txt") != 0) {
        strcat(filename, ".txt");
    }
}

// Function to read a file into a buffer
char* read_file(const char *filename, size_t *file_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file '%s'\n", filename);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    char *buffer = (char*)malloc(*file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    // Read file content
    size_t bytes_read = fread(buffer, 1, *file_size, file);
    if (bytes_read != *file_size) {
        free(buffer);
        fclose(file);
        return NULL;
    }

    buffer[*file_size] = '\0';
    fclose(file);
    return buffer;
}

// Function to write bit buffer to file
int write_compressed_file(const char *filename, BitBuffer *buffer) {
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;

    // Write the number of bits
    fwrite(&buffer->bit_position, sizeof(int), 1, file);

    // Write the actual data
    int bytes_to_write = (buffer->bit_position + 7) / 8;
    fwrite(buffer->data, 1, bytes_to_write, file);

    fclose(file);
    return 1;
}

// Function to read compressed file into bit buffer
BitBuffer* read_compressed_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;

    // Read the number of bits
    int bit_count;
    fread(&bit_count, sizeof(int), 1, file);

    // Calculate bytes needed
    int byte_count = (bit_count + 7) / 8;

    // Create bit buffer
    BitBuffer *buffer = create_bit_buffer(byte_count);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    // Read the data
    fread(buffer->data, 1, byte_count, file);
    buffer->bit_position = bit_count;

    fclose(file);
    return buffer;
}

// Function to compress a file
int compress_file(const char *input_filename, const char *output_filename) {
    // Read input file
    size_t file_size;
    char *input_text = read_file(input_filename, &file_size);
    if (!input_text) {
        printf("Error reading input file\n");
        return 1;
    }

    printf("Original file size: %zu bytes\n", file_size);

    // Build Huffman tree
    HuffmanTree *tree = build_tree_from_buffer(input_text);
    if (!tree) {
        printf("Error building Huffman tree\n");
        free(input_text);
        return 1;
    }

    // Build code table
    HuffmanCodeTable *code_table = build_code_table(tree);
    if (!code_table) {
        printf("Error building code table\n");
        free_huffman_tree_with_htable(tree->root);
        free(tree);
        free(input_text);
        return 1;
    }

    // Encode the text
    BitBuffer *encoded = encode_string(code_table, input_text);
    if (!encoded) {
        printf("Error encoding text\n");
        free_code_table(code_table);
        free_huffman_tree_with_htable(tree->root);
        free(tree);
        free(input_text);
        return 1;
    }

    // Write compressed file with coding table
    if (!write_compressed_file_with_table(output_filename, encoded, code_table)) {
        printf("Error writing compressed file\n");
        free_bit_buffer(encoded);
        free_code_table(code_table);
        free_huffman_tree_with_htable(tree->root);
        free(tree);
        free(input_text);
        return 1;
    }

    printf("Compressed file size: %d bytes\n", (encoded->bit_position + 7) / 8);
    printf("Compression ratio: %.2f%%\n", 
           (1.0 - (float)(encoded->bit_position + 7) / 8 / file_size) * 100);

    // Cleanup
    free_bit_buffer(encoded);
    free_code_table(code_table);
    free_huffman_tree_with_htable(tree->root);
    free(tree);
    free(input_text);

    return 0;
}

// Function to decompress a file
int decompress_file(const char *input_filename, const char *output_filename) {
    // Read compressed file with coding table
    HuffmanCodeTable *code_table;
    BitBuffer *compressed = read_compressed_file_with_table(input_filename, &code_table);
    if (!compressed) {
        printf("Error reading compressed file\n");
        return 1;
    }

    // Build Huffman tree from code table
    HuffmanTree *tree = build_huffman_tree_from_table(code_table);
    if (!tree) {
        printf("Error building Huffman tree from code table\n");
        free_bit_buffer(compressed);
        free_code_table(code_table);
        return 1;
    }

    // Decode the text
    char *decoded = decode_buffer(tree, compressed);
    if (!decoded) {
        printf("Error decoding text\n");
        free_bit_buffer(compressed);
        free_code_table(code_table);
        free_huffman_tree_with_htable(tree->root);
        free(tree);
        return 1;
    }

    // Write decompressed file
    FILE *output_file = fopen(output_filename, "w");
    if (!output_file) {
        printf("Error opening output file\n");
        free(decoded);
        free_bit_buffer(compressed);
        free_code_table(code_table);
        free_huffman_tree_with_htable(tree->root);
        free(tree);
        return 1;
    }

    fwrite(decoded, 1, strlen(decoded), output_file);
    fclose(output_file);

    // Cleanup
    free(decoded);
    free_bit_buffer(compressed);
    free_code_table(code_table);
    free_huffman_tree_with_htable(tree->root);
    free(tree);

    return 0;
}

#endif // FILE_API_H 