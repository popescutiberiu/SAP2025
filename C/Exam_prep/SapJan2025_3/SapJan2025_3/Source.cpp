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
        const char salt[8] = "ISMSalt";
        strcat(line, salt);
        


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

char* read_from_file(const char* filename) {
    FILE* f = fopen(filename, "rb");

    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    char* content = (char*)malloc(file_size + 1);
    if (!content) {
        perror("Memory allocation failed");
        fclose(f);
        return NULL;
    }

    fread(content, 1, file_size, f);
    content[file_size] = '\0';

    fclose(f);
    return content;
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

int search_file_index(const char* filename, const char* hashFile) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    char* hash = read_from_file(hashFile);

    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return 0;
    }

    int lineIndex = 0;
    while (fgets(line, sizeof(line), f)) {
        
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        if (strcmp(line, hash) == 1) {
            printf("hashFOund!");
            return lineIndex;
        }
       

        lineIndex++;
    }

    fclose(f);
    return 0;
}

void find_file_name(const char* filename, int index) {
    char line[MAX_LINE_LENGTH];


    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    int lineIndex = 0;
    while (fgets(line, sizeof(line), f)) {

        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        if (lineIndex==index) {
            for (int i = 0; i < 8;i++) {
                len--;
            }
            printf("\n");
            printf(line, index);
        }


        
        lineIndex++;
    }

    fclose(f);
}
int main() {
    decrypt_file_usingRSA("signature.sig", "RSAKey.pem", "decryptedSignature.txt");
    printFileInHex("decryptedSignature.txt");
    compute_sha_for_each_line_write_in_txt_file("wordlist.txt", "hashedwords.txt");
    //print_file_in_new_hex_file("decryptedSignature.txt", "decryptedHex.txt");
    //int fileIndex = search_file_index("hashedwords.txt", "decryptedHex.txt");
    //find_file_name("wordlist.txt", fileIndex);
}
