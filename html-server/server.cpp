#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

#define PORT 443
#define WEB_ROOT "/root/www/"  // Change this to your directory

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "/etc/letsencrypt/live/nextmessage.ai/fullchain.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/nextmessage.ai/privkey.pem", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "SSL Certificate/Key error\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        std::cerr << "Failed to enforce TLS 1.2+\n";
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5")) {
        std::cerr << "Failed to enforce strong ciphers\n";
        exit(EXIT_FAILURE);
    }
}

// Determine MIME type based on file extension (C++11 compatible)
std::string get_mime_type(const std::string& path) {
    if (path.rfind(".html") != std::string::npos) return "text/html";
    if (path.rfind(".css") != std::string::npos) return "text/css";
    if (path.rfind(".js") != std::string::npos) return "application/javascript";
    if (path.rfind(".png") != std::string::npos) return "image/png";
    if (path.rfind(".jpg") != std::string::npos || path.rfind(".jpeg") != std::string::npos) return "image/jpeg";
    if (path.rfind(".gif") != std::string::npos) return "image/gif";
    return "application/octet-stream";  // Default binary type
}

// Read file content into a string
std::string read_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Handle HTTP request and serve the requested file
void serve_client(SSL* ssl) {
    char request[1024] = {0};
    int bytes = SSL_read(ssl, request, sizeof(request) - 1);
    if (bytes <= 0) return;

    std::string request_str(request);
    std::cout << "Received Request:\n" << request_str << std::endl;

    // Extract method, path, and version from the request
    std::istringstream req_stream(request_str);
    std::string method, path, version;
    req_stream >> method >> path >> version;

    // Default to serving "index.html" if root is requested
    if (path == "/") path = "/index.html";

    // Construct the full file path
    std::string file_path = WEB_ROOT + path;

    // Read file content
    std::string content = read_file(file_path);
    bool file_found = !content.empty();

    // If file is missing, return 404 error page
    if (!file_found) {
        content = "<html><body><h1>404 Not Found</h1></body></html>";
        path = ".html";  // Force text/html MIME type for error page
    }

    // Determine correct MIME type
    std::string mime_type = get_mime_type(path);

    // Build HTTP response
    std::ostringstream response;
    response << "HTTP/1.1 " << (file_found ? "200 OK" : "404 Not Found") << "\r\n"
             << "Content-Type: " << mime_type << "\r\n"
             << "Content-Length: " << content.length() << "\r\n"
             << "Connection: close\r\n\r\n"
             << content;

    // Send response
    SSL_write(ssl, response.str().c_str(), response.str().length());
}

int main() {
    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "SSL Server listening on port " << PORT << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL Handshake failed\n";
            ERR_print_errors_fp(stderr);
        } else {
            std::cout << "SSL handshake successful\n";
            serve_client(ssl);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
