#include <iostream>
#include <getopt.h>
#include <openssl/evp.h>
#include <string>
#include <fstream>
#include <vector>

/**
 * @brief Prints usage information for the file encryption tool.
 *
 * This function outputs the usage details for encrypting or decrypting files.
 * It explains the command line options required to use the tool.
 */
void print_usage() {
    std::cout << "Usage: file_encrypt -e|-d -p <password> -i <input_file> -o <output_file>\n"
              << "-e: Encrypt the file\n"
              << "-d: Decrypt the file\n"
              << "-p: Password\n"
              << "-i: Input file path\n"
              << "-o: Output file path\n";
}

/**
 * @brief Main function for file encryption/decryption.
 *
 * This function takes command line arguments to perform encryption or decryption
 * of a specified file using a password-derived key. It uses the OpenSSL library
 * for the cryptographic operations.
 *
 * @param argc The number of command line arguments.
 * @param argv The array of command line arguments.
 * @return int Returns 0 if successful, otherwise returns an error code.
 */
int main(int argc, char* argv[]) {
    int opt;
    bool encrypt = false, decrypt = false;
    std::string password, input_file, output_file;

    // Parsing command line arguments
    while ((opt = getopt(argc, argv, "edp:i:o:")) != -1) {
        switch (opt) {
            case 'e':
                encrypt = true;
                break;
            case 'd':
                decrypt = true;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            default:
                print_usage();
                return EXIT_FAILURE;
        }
    }

    // Validate command line arguments
    if ((encrypt && decrypt) || (!encrypt && !decrypt) || password.empty() || input_file.empty() || output_file.empty()) {
        print_usage();
        return EXIT_FAILURE;
    }

    // Load the input file
    std::ifstream ifs(input_file, std::ios::binary);
    if (!ifs) {
        std::cerr << "Cannot open input file\n";
        return EXIT_FAILURE;
    }

    std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    // Generate key from password using PBKDF2
    unsigned char key[32];
    unsigned char iv[16] = {0}; // IV initialized to zero for simplicity

    /**
     * @brief Generates a key from the password using PBKDF2.
     *
     * Uses PKCS5_PBKDF2_HMAC to generate a 256-bit key from the user-provided password.
     *
     * @param password User-provided password.
     * @param key Generated key.
     * @return bool Returns true if key generation is successful, false otherwise.
     */
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), nullptr, 0, 10000, EVP_sha256(), 32, key)) {
        std::cerr << "Error generating key from password\n";
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    std::vector<unsigned char> output_data(file_data.size() + EVP_CIPHER_block_size(cipher));
    int output_len = 0, final_len = 0;

    // Perform encryption or decryption based on user choice
    if (encrypt) {
        EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
        EVP_EncryptUpdate(ctx, output_data.data(), &output_len, file_data.data(), file_data.size());
        EVP_EncryptFinal_ex(ctx, output_data.data() + output_len, &final_len);
    } else if (decrypt) {
        EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv);
        EVP_DecryptUpdate(ctx, output_data.data(), &output_len, file_data.data(), file_data.size());
        EVP_DecryptFinal_ex(ctx, output_data.data() + output_len, &final_len);
    }

    output_data.resize(output_len + final_len);
    EVP_CIPHER_CTX_free(ctx);

    // Write the result to the output file
    std::ofstream ofs(output_file, std::ios::binary);
    if (!ofs) {
        std::cerr << "Cannot open output file\n";
        return EXIT_FAILURE;
    }

    ofs.write(reinterpret_cast<const char*>(&output_data[0]), output_data.size());
    ofs.close();

    return EXIT_SUCCESS;
}
