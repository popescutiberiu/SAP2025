#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/applink.c>

#define INPUT_BLOCK_LENGTH 15
#define MAX_LINE_LENGTH 1024  // Maximum length of a line
#define IV_SIZE 16
#define KEY_SIZE 32  // Adjust based on AES-128 (16), AES-192 (24), or AES-256 (32)
#define AES_BLOCK_SIZE 16

void compute_sha_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* input_file = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!input_file || !output_file) {
        perror("Failed to open file");
        return;
    }

    while (fgets(line, sizeof(line), input_file)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }


        // Compute SHA-256 hash for the line
        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len);
        SHA256_Final(output_sha256, &context_sha256);



        // Write SHA-256 hash
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(output_file, "%02X ", output_sha256[i]);
        }

        fprintf(output_file, "\n");
    }

    fclose(input_file);
    fclose(output_file);
}

int encryptFileCBCLineByLine(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    // Basic checks
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters.\n");
        return 1;
    }
    // Validate key size
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return 2;
    }

    // Open input file
    FILE* fIn = fopen(inputFilename, "r");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Open output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        fclose(fIn);
        return 4;
    }

    // Initialize the AES encryption key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES encryption key.\n");
        fclose(fIn);
        fclose(fOut);
        return 5;
    }

    // Copy IV because AES_cbc_encrypt modifies it
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // Buffer to read lines
    // Increase this size if you expect very long lines
    char lineBuffer[1024];

    while (fgets(lineBuffer, sizeof(lineBuffer), fIn)) {
        size_t lineLen = strlen(lineBuffer);
        // Note: This line length includes the newline character if present
        // unless the line exactly filled the buffer (no newline until next iteration).

        // We will zero-pad any partial block just like the original code
        // Determine how many blocks we need for this line
        size_t partialBlock = (lineLen % AES_BLOCK_SIZE) ? 1 : 0;
        size_t blocks = (lineLen / AES_BLOCK_SIZE) + partialBlock;
        size_t encSize = blocks * AES_BLOCK_SIZE;

        // Prepare plaintext buffer (zero it out for padding)
        unsigned char* plaintext = (unsigned char*)calloc(encSize, 1);
        if (!plaintext) {
            fprintf(stderr, "Memory allocation error.\n");
            fclose(fIn);
            fclose(fOut);
            return 6;
        }
        memcpy(plaintext, lineBuffer, lineLen);

        // Allocate ciphertext buffer
        unsigned char* ciphertext = (unsigned char*)malloc(encSize);
        if (!ciphertext) {
            fprintf(stderr, "Memory allocation error.\n");
            free(plaintext);
            fclose(fIn);
            fclose(fOut);
            return 7;
        }

        // Encrypt using CBC
        AES_cbc_encrypt(plaintext, ciphertext, encSize, &aesKey, ivCopy, AES_ENCRYPT);

        // Write encrypted data to output
        fwrite(ciphertext, 1, encSize, fOut);

        // Clean up this iteration
        free(plaintext);
        free(ciphertext);
    }

    fclose(fIn);
    fclose(fOut);

    printf("File '%s' encrypted line-by-line (CBC) into '%s'.\n",
        inputFilename, outputFilename);
    return 0;
}

int main() {
    compute_sha_for_each_line_write_in_txt_file("wordlist.txt", "hashes.txt");
}