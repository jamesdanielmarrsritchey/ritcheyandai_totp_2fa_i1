#include <iostream>
#include <string>
#include <sstream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <ctime>
#include <vector> 
#include <unistd.h>
#include <getopt.h>

std::string base32_decode(const std::string &secret) {
    std::string decoded;
    std::string base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string padding_chars = "======";
    
    int padding_count = 0;
    for (char c : secret) {
        if (padding_chars.find(c) != std::string::npos) {
            padding_count++;
        }
    }
    
    int bit_count = (secret.size() * 5) - (padding_count * 5);
    int byte_count = bit_count / 8;
    
    std::vector<uint8_t> bytes(byte_count);
    int byte_index = 0;
    int bit_index = 0;
    
    for (char c : secret) {
        if (padding_chars.find(c) != std::string::npos) {
            break;
        }
        
        int value = base32_chars.find(c);
        if (value == std::string::npos) {
            // Invalid character
            return "";
        }
        
        for (int i = 4; i >= 0; i--) {
            bytes[byte_index] |= ((value >> i) & 1) << (7 - bit_index);
            bit_index++;
            if (bit_index == 8) {
                byte_index++;
                bit_index = 0;
            }
        }
    }
    
    decoded.assign(bytes.begin(), bytes.end());
    return decoded;
}

uint32_t dynamic_truncate(uint8_t *hash) {
    int offset = hash[19] & 0xf;
    return ((hash[offset] & 0x7f) << 24 |
            (hash[offset + 1] & 0xff) << 16 |
            (hash[offset + 2] & 0xff) << 8 |
            (hash[offset + 3] & 0xff)) % 1000000;
}

uint32_t totp(const std::string &secret, int interval = 30) {
    std::string decoded_secret = base32_decode(secret);
    uint64_t timestamp = std::time(nullptr) / interval;
    uint8_t msg[8];
    for (int i = 8; i--; timestamp >>= 8) {
        msg[i] = timestamp;
    }
    uint8_t hash[20];
    unsigned int len;
    HMAC(EVP_sha1(), decoded_secret.c_str(), decoded_secret.size(), msg, 8, hash, &len);
    return dynamic_truncate(hash);
}

int main(int argc, char *argv[]) {
    std::string secret;
    int opt;
    static struct option long_options[] = {
        {"private_key", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                secret = optarg;
                break;
            default:
                return 1;
        }
    }
    if (secret.empty()) {
        return 1;
    }
    std::cout << totp(secret) << std::endl;
    return 0;
}

/*
To compile this program, you need to have g++ and OpenSSL installed on your system.

On Debian, you can install these with the following commands:

    sudo apt-get update
    sudo apt-get install g++ libssl-dev

Once these are installed, you can compile the program with the following command:

    g++ -o program_name source.cpp -lcrypto

Replace "program_name" with the name you want to give to the compiled program, and "source.cpp" with the name of your source file.

To run the program, use the following command:

    ./program_name --private_key your_private_key

Replace "program_name" with the name of your compiled program, and "your_private_key" with your actual private key.
*/