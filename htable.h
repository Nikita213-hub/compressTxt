#ifndef HTABLE_H
#define HTABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//TODO: why do we store it in the htable.h????
// Structure to store UTF-8 character and its frequency
typedef struct UTF8Char {
    char *bytes;        // UTF-8 bytes of the character
    int byte_count;     // Number of bytes in the UTF-8 character
    int frequency;      // Frequency count
} UTF8Char;

// Node for the hash table chain
typedef struct HashNode {
    UTF8Char *data;
    struct HashNode *next;
} HashNode;

// Hash table structure
typedef struct HashTable {
    HashNode **buckets;
    int size;           // Number of buckets
    int count;          // Number of elements
} HashTable;

// Function to create a new UTF8Char
UTF8Char* create_utf8_char(const char *bytes, int byte_count) {
    UTF8Char *utf8 = (UTF8Char*)malloc(sizeof(UTF8Char));
    if (!utf8) return NULL;
    
    utf8->bytes = (char*)malloc(byte_count + 1);
    if (!utf8->bytes) {
        free(utf8);
        return NULL;
    }
    
    memcpy(utf8->bytes, bytes, byte_count);
    utf8->bytes[byte_count] = '\0';
    utf8->byte_count = byte_count;
    utf8->frequency = 1;
    
    return utf8;
}

// Function to free UTF8Char
void free_utf8_char(UTF8Char *utf8) {
    if (utf8) {
        free(utf8->bytes);
        free(utf8);
    }
}

// Hash function for UTF-8 strings
unsigned int hash_function(const char *key, int byte_count, int table_size) {
    unsigned int hash = 0;
    for (int i = 0; i < byte_count; i++) {
        hash = (hash * 31 + key[i]) % table_size;
    }
    return hash;
}

// Create a new hash table
HashTable* create_hash_table(int size) {
    HashTable *ht = (HashTable*)malloc(sizeof(HashTable));
    if (!ht) return NULL;
    
    ht->size = size;
    ht->count = 0;
    ht->buckets = (HashNode**)calloc(size, sizeof(HashNode*));
    if (!ht->buckets) {
        free(ht);
        return NULL;
    }
    
    return ht;
}

// Compare two UTF-8 characters
int compare_utf8_chars(const char *bytes1, int count1, const char *bytes2, int count2) {
    if (count1 != count2) return 0;
    return memcmp(bytes1, bytes2, count1) == 0;
}

// Insert or update a UTF-8 character in the hash table
void hash_table_insert(HashTable *ht, const char *bytes, int byte_count) {
    if (!ht || !bytes || byte_count <= 0) return;
    
    unsigned int index = hash_function(bytes, byte_count, ht->size);
    HashNode *current = ht->buckets[index];
    
    // Check if character already exists
    while (current) {
        if (compare_utf8_chars(current->data->bytes, current->data->byte_count, bytes, byte_count)) {
            current->data->frequency++;
            return;
        }
        current = current->next;
    }
    
    // Create new entry
    UTF8Char *utf8 = create_utf8_char(bytes, byte_count);
    if (!utf8) return;
    
    HashNode *new_node = (HashNode*)malloc(sizeof(HashNode));
    if (!new_node) {
        free_utf8_char(utf8);
        return;
    }
    
    new_node->data = utf8;
    new_node->next = ht->buckets[index];
    ht->buckets[index] = new_node;
    ht->count++;
}

// Get frequency of a UTF-8 character
int hash_table_get_frequency(HashTable *ht, const char *bytes, int byte_count) {
    if (!ht || !bytes || byte_count <= 0) return 0;
    
    unsigned int index = hash_function(bytes, byte_count, ht->size);
    HashNode *current = ht->buckets[index];
    
    while (current) {
        if (compare_utf8_chars(current->data->bytes, current->data->byte_count, bytes, byte_count)) {
            return current->data->frequency;
        }
        current = current->next;
    }
    
    return 0;
}

// Free hash table
void free_hash_table(HashTable *ht) {
    if (!ht) return;
    
    for (int i = 0; i < ht->size; i++) {
        HashNode *current = ht->buckets[i];
        while (current) {
            HashNode *temp = current;
            current = current->next;
            free_utf8_char(temp->data);
            free(temp);
        }
    }
    
    free(ht->buckets);
    free(ht);
}

// Function to iterate through all entries in the hash table
void hash_table_iterate(HashTable *ht, void (*callback)(UTF8Char*)) {
    if (!ht || !callback) return;
    
    for (int i = 0; i < ht->size; i++) {
        HashNode *current = ht->buckets[i];
        while (current) {
            callback(current->data);
            current = current->next;
        }
    }
}

#endif // HTABLE_H 