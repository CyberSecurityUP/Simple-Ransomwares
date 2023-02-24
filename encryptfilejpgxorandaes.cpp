#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// Define the key and IV lengths
const int KEY_LENGTH = 32;
const int IV_LENGTH = 16;

// Encrypt the input file using AES-256-CBC
int encrypt_file(string input_file_path, string output_file_path, string key, string iv) {
    // Open the input file in binary mode
    ifstream input_file(input_file_path, ios::binary);
    if (!input_file) {
        cerr << "Error: Could not open input file." << endl;
        return 1;
    }

    // Open the output file in binary mode
    ofstream output_file(output_file_path, ios::binary);
    if (!output_file) {
        cerr << "Error: Could not open output file." << endl;
        return 1;
    }

    // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Apply XOR encryption to the key
    for (int i = 0; i < key.length(); i++) {
        key[i] ^= 0xAA;
    }

    // Set up the encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Could not create encryption context." << endl;
        return 1;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str())) {
        cerr << "Error: Could not initialize encryption context." << endl;
        return 1;
    }

    // Read the input file in blocks and encrypt each block
    const int BLOCK_SIZE = 4096;
    char in_buf[BLOCK_SIZE];
    char out_buf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    while (input_file.read(in_buf, BLOCK_SIZE)) {
        in_len = input_file.gcount();
        if (!EVP_EncryptUpdate(ctx, (unsigned char*)out_buf, &out_len, (unsigned char*)in_buf, in_len)) {
            cerr << "Error: Could not encrypt input data." << endl;
            return 1;
        }
        output_file.write(out_buf, out_len);
    }

    // Finalize the encryption process
    if (!EVP_EncryptFinal_ex(ctx, (unsigned char*)out_buf, &out_len)) {
        cerr << "Error: Could not finalize encryption process." << endl;
        return 1;
    }
    output_file.write(out_buf, out_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();

    return 0;
}

// Decrypt the input file using AES-256-CBC
int decrypt_file(string input_file_path, string output_file_path, string key, string iv) {
    // Open the input file in binary mode
    ifstream input_file(input_file_path, ios::binary);
    if (!input_file) {
        cerr << "Error: Could not open input file." << endl;
        return 1;
    }

    // Open the output file in binary mode
    ofstream output_file(output_file_path, ios::binary);
    if (!output_file) {
        cerr << "Error: Could not open output file." << endl
