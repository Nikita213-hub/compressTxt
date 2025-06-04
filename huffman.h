#ifndef HUFFMAN_H
#define HUFFMAN_H

#include "htable.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Huffman tree node structure
typedef struct HuffmanNode {
    struct HuffmanNode *left;
    struct HuffmanNode *right;
    UTF8Char *data;     // UTF-8 character data (NULL for internal nodes)
    int frequency;      // Frequency count
} HuffmanNode;

// Huffman tree structure
typedef struct HuffmanTree {
    HuffmanNode *root;
} HuffmanTree;

// Priority queue node
typedef struct PriorityQueueNode {
    HuffmanNode *data;
    int priority;
    struct PriorityQueueNode *next;
} PriorityQueueNode;

// Priority queue structure
typedef struct PriorityQueue {
    PriorityQueueNode *first;
    int size;
} PriorityQueue;

// Structure for Huffman code table entry
typedef struct HuffmanCode {
    UTF8Char *symbol;    // The UTF-8 character
    unsigned int code;   // The code (stored as bits)
    int code_length;     // Number of bits in the code
} HuffmanCode;

// Structure for the code table
typedef struct HuffmanCodeTable {
    HuffmanCode *codes;
    int size;
    int capacity;
} HuffmanCodeTable;

// Create a new Huffman node
HuffmanNode* create_huffman_node(UTF8Char *data, int frequency) {
    HuffmanNode *node = (HuffmanNode*)malloc(sizeof(HuffmanNode));
    if (!node) return NULL;
    
    node->left = NULL;
    node->right = NULL;
    node->data = data;
    node->frequency = frequency;
    
    return node;
}

// Initialize priority queue
void init_priority_queue(PriorityQueue **queue) {
    *queue = (PriorityQueue*)malloc(sizeof(PriorityQueue));
    if (!*queue) return;
    
    (*queue)->first = NULL;
    (*queue)->size = 0;
}

// Add node to priority queue
void add_to_queue(PriorityQueue *queue, HuffmanNode *node, int priority) {
    if (!queue || !node) return;
    
    PriorityQueueNode *new_node = (PriorityQueueNode*)malloc(sizeof(PriorityQueueNode));
    if (!new_node) return;
    
    new_node->data = node;
    new_node->priority = priority;
    new_node->next = NULL;
    
    // Insert at the beginning if queue is empty or new node has higher priority
    if (!queue->first || priority < queue->first->priority) {
        new_node->next = queue->first;
        queue->first = new_node;
    } else {
        // Find the correct position
        PriorityQueueNode *current = queue->first;
        while (current->next && priority >= current->next->priority) {
            current = current->next;
        }
        new_node->next = current->next;
        current->next = new_node;
    }
    queue->size++;
}

// Get node with highest priority (lowest frequency)
HuffmanNode* get_from_queue(PriorityQueue *queue) {
    if (!queue || !queue->first) return NULL;
    
    PriorityQueueNode *temp = queue->first;
    HuffmanNode *data = temp->data;
    queue->first = temp->next;
    queue->size--;
    free(temp);
    
    return data;
}

// Free priority queue
void free_priority_queue(PriorityQueue *queue) {
    if (!queue) return;
    
    while (queue->first) {
        PriorityQueueNode *temp = queue->first;
        queue->first = temp->next;
        free(temp);
    }
    free(queue);
}

// Build Huffman tree from hash table
HuffmanTree* build_huffman_tree(HashTable *ht) {
    if (!ht || ht->count == 0) return NULL;
    
    // Create priority queue
    PriorityQueue *queue;
    init_priority_queue(&queue);
    
    // Add all characters to the queue
    for (int i = 0; i < ht->size; i++) {
        HashNode *current = ht->buckets[i];
        while (current) {
            HuffmanNode *node = create_huffman_node(current->data, current->data->frequency);
            if (node) {
                add_to_queue(queue, node, current->data->frequency);
            }
            current = current->next;
        }
    }
    
    // Build the tree
    while (queue->size > 1) {
        // Get two nodes with lowest frequency
        HuffmanNode *left = get_from_queue(queue);
        HuffmanNode *right = get_from_queue(queue);
        
        // Create new internal node
        HuffmanNode *internal = create_huffman_node(NULL, left->frequency + right->frequency);
        if (!internal) {
            // Handle memory allocation error
            free_priority_queue(queue);
            return NULL;
        }
        
        internal->left = left;
        internal->right = right;
        
        // Add the new node back to the queue
        add_to_queue(queue, internal, internal->frequency);
    }
    
    // Create the tree
    HuffmanTree *tree = (HuffmanTree*)malloc(sizeof(HuffmanTree));
    if (!tree) {
        free_priority_queue(queue);
        return NULL;
    }
    
    tree->root = get_from_queue(queue);
    free_priority_queue(queue);
    
    return tree;
}

// Free Huffman tree
void free_huffman_tree(HuffmanNode *node) {
    if (!node) return;
    
    free_huffman_tree(node->left);
    free_huffman_tree(node->right);
    free(node);
}

// Function to get UTF-8 character length from first byte
int get_utf8_char_length(unsigned char first_byte) {
    if ((first_byte & 0x80) == 0) return 1;  // ASCII
    if ((first_byte & 0xE0) == 0xC0) return 2;  // 2-byte UTF-8
    if ((first_byte & 0xF0) == 0xE0) return 3;  // 3-byte UTF-8
    if ((first_byte & 0xF8) == 0xF0) return 4;  // 4-byte UTF-8
    return 1;  // Invalid UTF-8, treat as single byte
}

// Build Huffman tree from raw text buffer
HuffmanTree* build_tree_from_buffer(const char *buffer) {
    if (!buffer) return NULL;
    
    // Create hash table for character frequencies
    HashTable *ht = create_hash_table(256);  // Size can be adjusted based on expected number of unique characters
    
    // Process the buffer character by character
    int i = 0;
    while (buffer[i] != '\0') {
        // Get the length of the current UTF-8 character
        int char_len = get_utf8_char_length(buffer[i]);
        
        // Insert the complete UTF-8 character into the hash table
        hash_table_insert(ht, &buffer[i], char_len);
        
        // Move to the next character
        i += char_len;
    }
    
    // Build the Huffman tree from the hash table
    HuffmanTree *tree = build_huffman_tree(ht);
    
    // We don't free the hash table here because the tree nodes are using its data
    // The hash table will be freed when the tree is freed
    
    return tree;
}

// Modified free_huffman_tree to also free the hash table data
void free_huffman_tree_with_htable(HuffmanNode *node) {
    if (!node) return;
    
    free_huffman_tree_with_htable(node->left);
    free_huffman_tree_with_htable(node->right);
    
    // Free the UTF8Char data if this is a leaf node
    if (node->data) {
        free_utf8_char(node->data);
    }
    
    free(node);
}

// Create a new code table
HuffmanCodeTable* create_code_table(int initial_capacity) {
    HuffmanCodeTable *table = (HuffmanCodeTable*)malloc(sizeof(HuffmanCodeTable));
    if (!table) return NULL;
    
    table->codes = (HuffmanCode*)malloc(sizeof(HuffmanCode) * initial_capacity);
    if (!table->codes) {
        free(table);
        return NULL;
    }
    
    table->size = 0;
    table->capacity = initial_capacity;
    return table;
}

// Add a code to the table
void add_code_to_table(HuffmanCodeTable *table, UTF8Char *symbol, unsigned int code, int code_length) {
    if (table->size >= table->capacity) {
        // Resize the table
        table->capacity *= 2;
        table->codes = (HuffmanCode*)realloc(table->codes, sizeof(HuffmanCode) * table->capacity);
    }
    
    table->codes[table->size].symbol = symbol;
    table->codes[table->size].code = code;
    table->codes[table->size].code_length = code_length;
    table->size++;
}

// Recursive function to build the code table
void build_code_table_recursive(HuffmanNode *node, HuffmanCodeTable *table, unsigned int code, int code_length) {
    if (!node) return;
    
    if (node->data) {
        // Leaf node - add the code to the table
        add_code_to_table(table, node->data, code, code_length);
    } else {
        // Internal node - continue building codes
        build_code_table_recursive(node->left, table, code << 1, code_length + 1);
        build_code_table_recursive(node->right, table, (code << 1) | 1, code_length + 1);
    }
}

// Build the code table from the Huffman tree
HuffmanCodeTable* build_code_table(HuffmanTree *tree) {
    if (!tree || !tree->root) return NULL;
    
    HuffmanCodeTable *table = create_code_table(256);  // Initial capacity
    if (!table) return NULL;
    
    build_code_table_recursive(tree->root, table, 0, 0);
    return table;
}

// Free the code table
void free_code_table(HuffmanCodeTable *table) {
    if (!table) return;
    free(table->codes);
    free(table);
}

// Structure for bit buffer
typedef struct BitBuffer {
    unsigned char *data;
    int size;           // Size in bytes
    int bit_position;   // Current bit position
} BitBuffer;

// Create a new bit buffer
BitBuffer* create_bit_buffer(int initial_size) {
    BitBuffer *buffer = (BitBuffer*)malloc(sizeof(BitBuffer));
    if (!buffer) return NULL;
    
    buffer->data = (unsigned char*)calloc(initial_size, sizeof(unsigned char));
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }
    
    buffer->size = initial_size;
    buffer->bit_position = 0;
    return buffer;
}

// Write a bit to the buffer
void write_bit(BitBuffer *buffer, int bit) {
    if (buffer->bit_position / 8 >= buffer->size) {
        // Resize buffer
        buffer->size *= 2;
        buffer->data = (unsigned char*)realloc(buffer->data, buffer->size);
    }
    
    if (bit) {
        buffer->data[buffer->bit_position / 8] |= (1 << (7 - (buffer->bit_position % 8)));
    }
    buffer->bit_position++;
}

// Read a bit from the buffer
int read_bit(BitBuffer *buffer, int position) {
    if (position >= buffer->bit_position) return -1;
    return (buffer->data[position / 8] >> (7 - (position % 8))) & 1;
}

// Encode a string using the Huffman codes
BitBuffer* encode_string(HuffmanCodeTable *table, const char *input) {
    if (!table || !input) return NULL;
    
    BitBuffer *buffer = create_bit_buffer(256);
    if (!buffer) return NULL;
    
    int i = 0;
    while (input[i] != '\0') {
        // Get UTF-8 character length
        int char_len = get_utf8_char_length(input[i]);
        
        // Find the code for this character
        for (int j = 0; j < table->size; j++) {
            if (memcmp(table->codes[j].symbol->bytes, &input[i], char_len) == 0) {
                // Write the code bits
                for (int k = 0; k < table->codes[j].code_length; k++) {
                    write_bit(buffer, (table->codes[j].code >> (table->codes[j].code_length - 1 - k)) & 1);
                }
                break;
            }
        }
        
        i += char_len;
    }
    
    return buffer;
}

// Decode a bit buffer using the Huffman tree
char* decode_buffer(HuffmanTree *tree, BitBuffer *buffer) {
    if (!tree || !buffer) return NULL;
    
    // Allocate output buffer (estimate size)
    char *output = (char*)malloc(buffer->bit_position + 1);
    if (!output) return NULL;
    
    int output_pos = 0;
    HuffmanNode *current = tree->root;
    
    for (int i = 0; i < buffer->bit_position; i++) {
        int bit = read_bit(buffer, i);
        if (bit == -1) break;
        
        current = bit ? current->right : current->left;
        
        if (current->data) {
            // Found a character
            memcpy(&output[output_pos], current->data->bytes, current->data->byte_count);
            output_pos += current->data->byte_count;
            current = tree->root;
        }
    }
    
    output[output_pos] = '\0';
    return output;
}

// Free bit buffer
void free_bit_buffer(BitBuffer *buffer) {
    if (!buffer) return;
    free(buffer->data);
    free(buffer);
}

// Function to save coding table to file
int save_code_table(FILE *file, HuffmanCodeTable *table) {
    if (!file || !table) return 0;

    // Write number of codes
    fwrite(&table->size, sizeof(int), 1, file);

    // Write each code entry
    for (int i = 0; i < table->size; i++) {
        // Write UTF-8 character length and bytes
        fwrite(&table->codes[i].symbol->byte_count, sizeof(int), 1, file);
        fwrite(table->codes[i].symbol->bytes, 1, table->codes[i].symbol->byte_count, file);
        
        // Write code and code length
        fwrite(&table->codes[i].code, sizeof(unsigned int), 1, file);
        fwrite(&table->codes[i].code_length, sizeof(int), 1, file);
    }

    return 1;
}

// Function to load coding table from file
HuffmanCodeTable* load_code_table(FILE *file) {
    if (!file) return NULL;

    // Read number of codes
    int size;
    if (fread(&size, sizeof(int), 1, file) != 1) return NULL;

    // Create code table
    HuffmanCodeTable *table = create_code_table(size);
    if (!table) return NULL;

    // Read each code entry
    for (int i = 0; i < size; i++) {
        // Read UTF-8 character
        int byte_count;
        if (fread(&byte_count, sizeof(int), 1, file) != 1) {
            free_code_table(table);
            return NULL;
        }

        char *bytes = (char*)malloc(byte_count);
        if (!bytes) {
            free_code_table(table);
            return NULL;
        }

        if (fread(bytes, 1, byte_count, file) != byte_count) {
            free(bytes);
            free_code_table(table);
            return NULL;
        }

        // Create UTF8Char
        UTF8Char *utf8 = create_utf8_char(bytes, byte_count);
        free(bytes);
        if (!utf8) {
            free_code_table(table);
            return NULL;
        }

        // Read code and code length
        unsigned int code;
        int code_length;
        if (fread(&code, sizeof(unsigned int), 1, file) != 1 ||
            fread(&code_length, sizeof(int), 1, file) != 1) {
            free_utf8_char(utf8);
            free_code_table(table);
            return NULL;
        }

        // Add to table
        add_code_to_table(table, utf8, code, code_length);
    }

    return table;
}

// Function to write compressed file with coding table
int write_compressed_file_with_table(const char *filename, BitBuffer *buffer, HuffmanCodeTable *table) {
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;

    // Write coding table
    if (!save_code_table(file, table)) {
        fclose(file);
        return 0;
    }

    // Write the number of bits
    fwrite(&buffer->bit_position, sizeof(int), 1, file);

    // Write the actual data
    int bytes_to_write = (buffer->bit_position + 7) / 8;
    fwrite(buffer->data, 1, bytes_to_write, file);

    fclose(file);
    return 1;
}

// Function to read compressed file with coding table
BitBuffer* read_compressed_file_with_table(const char *filename, HuffmanCodeTable **table) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;

    // Load coding table
    *table = load_code_table(file);
    if (!*table) {
        fclose(file);
        return NULL;
    }

    // Read the number of bits
    int bit_count;
    if (fread(&bit_count, sizeof(int), 1, file) != 1) {
        free_code_table(*table);
        fclose(file);
        return NULL;
    }

    // Calculate bytes needed
    int byte_count = (bit_count + 7) / 8;

    // Create bit buffer
    BitBuffer *buffer = create_bit_buffer(byte_count);
    if (!buffer) {
        free_code_table(*table);
        fclose(file);
        return NULL;
    }

    // Read the data
    if (fread(buffer->data, 1, byte_count, file) != byte_count) {
        free_bit_buffer(buffer);
        free_code_table(*table);
        fclose(file);
        return NULL;
    }

    buffer->bit_position = bit_count;
    fclose(file);
    return buffer;
}

// Function to build Huffman tree from code table
HuffmanTree* build_huffman_tree_from_table(HuffmanCodeTable *table) {
    if (!table || table->size == 0) return NULL;

    // Create the tree
    HuffmanTree *tree = (HuffmanTree*)malloc(sizeof(HuffmanTree));
    if (!tree) return NULL;

    // Start with root node
    tree->root = create_huffman_node(NULL, 0);
    if (!tree->root) {
        free(tree);
        return NULL;
    }

    // For each code in the table
    for (int i = 0; i < table->size; i++) {
        HuffmanNode *current = tree->root;
        unsigned int code = table->codes[i].code;
        int code_length = table->codes[i].code_length;

        // Traverse the code bits to build the tree
        for (int j = 0; j < code_length; j++) {
            int bit = (code >> (code_length - 1 - j)) & 1;

            if (bit) {
                // Right child
                if (!current->right) {
                    current->right = create_huffman_node(NULL, 0);
                    if (!current->right) {
                        free_huffman_tree_with_htable(tree->root);
                        free(tree);
                        return NULL;
                    }
                }
                current = current->right;
            } else {
                // Left child
                if (!current->left) {
                    current->left = create_huffman_node(NULL, 0);
                    if (!current->left) {
                        free_huffman_tree_with_htable(tree->root);
                        free(tree);
                        return NULL;
                    }
                }
                current = current->left;
            }
        }

        // At the leaf node, set the character data
        current->data = table->codes[i].symbol;
    }

    return tree;
}

#endif // HUFFMAN_H 