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


int decrypt_file_usingRSA(const char* encrypted_bin_file,
    const char* private_key_file,
    const char* restored_file)
{
    FILE* fdst = NULL, * fprivkey = NULL, * frest = NULL;
    RSA* privkey = NULL;
    unsigned char* data = NULL;
    unsigned char* out = NULL;
    int key_size, enc_file_size, no_blocks;
    int dec_size;
    int ret = 1;  // non-zero on error, 0 on success

    // Open the encrypted binary file
    fdst = fopen(encrypted_bin_file, "rb");
    if (!fdst) {
        perror("Failed to open encrypted_bin_file for reading");
        goto cleanup;
    }

    // Open the private key
    fprivkey = fopen(private_key_file, "rb");
    if (!fprivkey) {
        perror("Failed to open private_key_file");
        goto cleanup;
    }

    privkey = PEM_read_RSAPublicKey(fprivkey, NULL, NULL, NULL);
    if (!privkey) {
        fprintf(stderr, "Error reading RSA private key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Determine the RSA key size
    key_size = RSA_size(privkey);

    // Determine how many blocks in the encrypted file
    fseek(fdst, 0, SEEK_END);
    enc_file_size = ftell(fdst);
    fseek(fdst, 0, SEEK_SET);

    no_blocks = enc_file_size / key_size;
    if (no_blocks <= 0) {
        fprintf(stderr, "Encrypted file size is too small or invalid.\n");
        goto cleanup;
    }

    // Prepare output file
    frest = fopen(restored_file, "wb");
    if (!frest) {
        perror("Failed to open restored_file");
        goto cleanup;
    }

    data = (unsigned char*)malloc(key_size);
    out = (unsigned char*)malloc(key_size);
    if (!data || !out) {
        fprintf(stderr, "Memory allocation failure\n");
        goto cleanup;
    }

    // Decrypt the first (n-1) blocks with NO_PADDING
    for (int i = 0; i < no_blocks - 1; i++) {
        if (fread(data, 1, key_size, fdst) != (size_t)key_size) {
            fprintf(stderr, "Failed to read the expected block from file\n");
            goto cleanup;
        }

        dec_size = RSA_public_decrypt(key_size, data, out, privkey, RSA_NO_PADDING);
        if (dec_size < 0) {
            fprintf(stderr, "RSA_private_decrypt error (NO_PADDING block)\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        // Write all decrypted bytes for these blocks
        fwrite(out, 1, dec_size, frest);
    }

    // Decrypt the last block with PKCS1_PADDING
    if (fread(data, 1, key_size, fdst) == (size_t)key_size) {
        dec_size = RSA_public_decrypt(key_size, data, out, privkey, RSA_PKCS1_PADDING);
        if (dec_size < 0) {
            fprintf(stderr, "RSA_private_decrypt error (PKCS1 block)\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        // Only write the actual decrypted size for the last block
        fwrite(out, 1, dec_size, frest);
    }
    else {
        fprintf(stderr, "Error reading the final block.\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (fdst) fclose(fdst);
    if (fprivkey) fclose(fprivkey);
    if (frest) fclose(frest);
    if (privkey) RSA_free(privkey);
    if (data) free(data);
    if (out) free(out);
    return ret;
}


void printFileInHex(const char* filename) {
    FILE* f = fopen(filename, "rb");  // Open file in binary mode

    if (!f) {
        perror("Failed to open file");
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);  // Go back to the beginning

    char* content = (char*)malloc(file_size);
    if (!content) {
        perror("Memory allocation failed");
        fclose(f);
        return;
    }

    size_t bytesRead = fread(content, 1, file_size, f);
    if (bytesRead != file_size) {
        perror("File read error");
        free(content);
        fclose(f);
        return;
    }

    // Print each byte in hex format
    for (long i = 0; i < file_size; i++) {
        printf("%02X ", (unsigned char)content[i]);
        // Optional: add a newline every 16 bytes for readability
        
    }
    printf("\n");

    free(content);
    fclose(f);
}

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
        strcat(line, "ISMsalt");


        // Compute SHA-256 hash for the line
        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len+7);
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

int find_sha_line(const char* text_filename, const char* sha_filename) {
    char line[MAX_LINE_LENGTH];
    char shaLine[MAX_LINE_LENGTH];

    FILE* text_file = fopen(text_filename, "r");
    FILE* sha_file = fopen(sha_filename, "r");
    fgets(shaLine, sizeof(shaLine), text_file);

    if (!text_file || !sha_file) {
        perror("Failed to open file");
        return 0;
    }
    int lineIndex = 0;

    while (fgets(line, sizeof(line), sha_file) ) {
        size_t len = strlen(line);

        
        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        if (strcmp(shaLine, line) == 0) {
            printf("Line found");
            return lineIndex;
        }
        lineIndex++;
        
        
    }

    fclose(text_file);
    fclose(sha_file);
    return 0;
}

void find_index_line(const char* text_filename, int index) {
    char line[MAX_LINE_LENGTH];

    FILE* text_file = fopen(text_filename, "r");

    if (!text_file ) {
        perror("Failed to open file");
        return;
    }
    int lineIndex = 0;

    while (fgets(line, sizeof(line), text_file)) {
        size_t len = strlen(line);


        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        
        if (lineIndex == index) {
            printf("the line is %s at index %d", line, lineIndex);
            break;
        }

        lineIndex++;


    }

    fclose(text_file);
}

void print_file_in_new_hex_file(const char* filename, const char* output_filename) {
    FILE* file = fopen(filename, "rb");
    FILE* output_file = fopen(output_filename, "w");
    if (!file) {
        perror("Failed to open file for reading");
        return;
    }

    unsigned char buffer[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            fprintf(output_file, "%02X ", buffer[i]);
        }
    }

    printf("\n");
    fclose(file);
    fclose(output_file);
}

void write_in_file(const char* filename, const char* content) {

    //wb for binary writing
    FILE* f = fopen(filename, "w");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    fprintf(f, "%s", content);

    printf("Content written succesfully!\n");

    fclose(f);
}

int encryptFileCBC(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    // Sanity checks:
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters provided to encryptFileCBC.\n");
        return 1;
    }
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes.\n");
        return 2;
    }

    // Open the input file for reading
    FILE* fIn = fopen(inputFilename, "rb");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Determine the size of the input file
    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    if (fileSize <= 0) {
        fprintf(stderr, "Input file is empty or error reading size.\n");
        fclose(fIn);
        return 4;
    }

    // Read the entire file into plaintext buffer
    unsigned char* plaintext = (unsigned char*)malloc(fileSize);
    if (!plaintext) {
        fprintf(stderr, "Failed to allocate memory for plaintext.\n");
        fclose(fIn);
        return 5;
    }
    if (fread(plaintext, 1, fileSize, fIn) != (size_t)fileSize) {
        fprintf(stderr, "Error reading input file.\n");
        free(plaintext);
        fclose(fIn);
        return 6;
    }
    fclose(fIn);

    // Compute size for ciphertext buffer
    // Similar to your snippet, it doesn't do official padding but does block rounding.
    size_t partial_block = (fileSize % AES_BLOCK_SIZE) ? 1 : 0;
    size_t blocks = (fileSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = blocks * AES_BLOCK_SIZE;

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        free(plaintext);
        return 7;
    }

    // Prepare the AES key structure
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set encrypt key.\n");
        free(plaintext);
        free(ciphertext);
        return 8;
    }

    // Copy IV locally, because AES_cbc_encrypt modifies the IV
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // Encrypt (CBC)
    AES_cbc_encrypt(plaintext, ciphertext, fileSize, &aesKey, ivCopy, AES_ENCRYPT);

    // Write the ciphertext to the output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        free(plaintext);
        free(ciphertext);
        return 9;
    }

    fwrite(ciphertext, 1, ciphertextSize, fOut);
    fclose(fOut);

    // Cleanup
    free(plaintext);
    free(ciphertext);

    printf("File '%s' encrypted successfully into '%s'\n", inputFilename, outputFilename);
    return 0;
}


int read_aes_key(const char* filename, unsigned char* key) {
    FILE* keyFile = fopen(filename, "rb");
    if (!keyFile) {
        perror("Failed to open key file");
        return 1;  // Return error
    }

    size_t bytesRead = fread(key, 1, KEY_SIZE, keyFile);
    fclose(keyFile);

    if (bytesRead != KEY_SIZE) {
        fprintf(stderr, "Error: Expected %d bytes but read %zu bytes.\n", KEY_SIZE, bytesRead);
        return 1;  // Return error
    }

    return 0;  // Success
}

int main() {
    decrypt_file_usingRSA("signature.sig", "RSAKey.pem", "restored.txt");
    printFileInHex("restored.txt");
    compute_sha_for_each_line_write_in_txt_file("wordlist.txt", "hashList.txt");
    print_file_in_new_hex_file("restored.txt", "restoredHex.txt");
    int foundIndex = find_sha_line("restoredHex.txt", "hashList.txt");
    printf("\n%d",foundIndex);
    printf("\n");
    find_index_line("wordlist.txt", foundIndex);
    printf("\n");

    write_in_file("word.txt", "Starwars");
    unsigned char key[KEY_SIZE];
    read_aes_key("restored.txt", key);
    printf("key value:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", key[i]);
    }
    unsigned char iv[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    encryptFileCBC("word.txt", "word.enc", key, KEY_SIZE, iv);
}