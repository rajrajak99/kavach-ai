#include <iostream>
#include <cstring>
#include <cstdlib>

void handle_request(const char* user_input, const char* filename) {
    // 1. Hardcoded Secret Key (CWE-798)
    const char* api_key = "ghp_ProductionSecretKey998877665544332211";

    // 2. Buffer Overflow Vulnerability (CWE-120)
    char buffer[64];
    strcpy(buffer, user_input);

    // 3. Format String Vulnerability (CWE-134)
    printf(buffer);

    // 4. Command Injection via system() (CWE-78)
    std::string cmd = "ping -c 1 " + std::string(filename);
    system(cmd.c_str());
}

int main() {
    std::cout << "Starting server..." << std::endl;
    return 0;
}
