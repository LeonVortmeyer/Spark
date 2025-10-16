#include "Connection.H"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>
#include <iostream>

namespace electronx {
namespace fix {
namespace tls {

bool Connection::ssl_initialized_ = false;

Connection::Connection(const Config& config)
    : config_(config) {
    init_ssl_library();
}

Connection::~Connection() {
    disconnect();
}

void Connection::init_ssl_library() {
    if (!ssl_initialized_) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialized_ = true;
    }
}

void Connection::cleanup_ssl_library() {
    if (ssl_initialized_) {
        EVP_cleanup();
        ERR_free_strings();
        ssl_initialized_ = false;
    }
}

bool Connection::connect() {
    if (state_ == ConnectionState::CONNECTED) {
        return true;
    }

    set_state(ConnectionState::CONNECTING);

    // Initialize SSL context
    if (!init_ssl_context()) {
        set_state(ConnectionState::ERROR);
        return false;
    }

    // Create and connect socket
    if (!create_socket()) {
        cleanup_ssl();
        set_state(ConnectionState::ERROR);
        return false;
    }

    // Perform SSL handshake
    if (!ssl_handshake()) {
        cleanup_ssl();
        set_state(ConnectionState::ERROR);
        return false;
    }

    set_state(ConnectionState::CONNECTED);

    if (on_connected_) {
        on_connected_();
    }

    return true;
}

void Connection::disconnect() {
    if (state_ == ConnectionState::DISCONNECTED) {
        return;
    }

    set_state(ConnectionState::DISCONNECTING);
    cleanup_ssl();
    set_state(ConnectionState::DISCONNECTED);

    if (on_disconnected_) {
        on_disconnected_();
    }
}

bool Connection::init_ssl_context() {
    // Create SSL context with TLS method
    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) {
        set_error("Failed to create SSL context");
        return false;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);

    // Load client certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx_,
                                     config_.client_cert_path.c_str(),
                                     SSL_FILETYPE_PEM) <= 0) {
        set_error("Failed to load client certificate: " + config_.client_cert_path);
        return false;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_,
                                    config_.client_key_path.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
        set_error("Failed to load private key: " + config_.client_key_path);
        return false;
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        set_error("Private key does not match certificate");
        return false;
    }

    // Load CA certificate for server verification
    if (SSL_CTX_load_verify_locations(ssl_ctx_,
                                      config_.ca_cert_path.c_str(),
                                      nullptr) <= 0) {
        set_error("Failed to load CA certificate: " + config_.ca_cert_path);
        return false;
    }

    // Set verification mode - require server certificate
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);

    return true;
}

bool Connection::create_socket() {
    // Resolve hostname
    struct addrinfo hints, *servinfo, *p;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(config_.host.c_str(),
                        std::to_string(config_.port).c_str(),
                        &hints,
                        &servinfo);
    if (rv != 0) {
        set_error("Failed to resolve host: " + std::string(gai_strerror(rv)));
        return false;
    }

    // Try each address until we successfully connect
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        socket_fd_ = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socket_fd_ == -1) {
            continue;
        }

        // Enable TCP keepalive
        int keepalive = 1;
        setsockopt(socket_fd_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

        // Set TCP_NODELAY to disable Nagle's algorithm
        int nodelay = 1;
        setsockopt(socket_fd_, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = config_.socket_timeout_ms / 1000;
        timeout.tv_usec = (config_.socket_timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        // Connect
        if (::connect(socket_fd_, p->ai_addr, p->ai_addrlen) == -1) {
            close(socket_fd_);
            socket_fd_ = -1;
            continue;
        }

        break; // Successfully connected
    }

    freeaddrinfo(servinfo);

    if (socket_fd_ == -1) {
        set_error("Failed to connect to " + config_.host + ":" + std::to_string(config_.port));
        return false;
    }

    return true;
}

bool Connection::ssl_handshake() {
    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) {
        set_error("Failed to create SSL object");
        return false;
    }

    SSL_set_fd(ssl_, socket_fd_);

    // Perform SSL handshake
    int ret = SSL_connect(ssl_);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        set_error("SSL handshake failed: " + std::string(err_buf));
        return false;
    }

    // Verify server certificate
    X509* cert = SSL_get_peer_certificate(ssl_);
    if (!cert) {
        set_error("Server did not provide a certificate");
        return false;
    }
    X509_free(cert);

    long verify_result = SSL_get_verify_result(ssl_);
    if (verify_result != X509_V_OK) {
        set_error("Server certificate verification failed: " +
                 std::string(X509_verify_cert_error_string(verify_result)));
        return false;
    }

    // Set to non-blocking mode after handshake
    if (!set_non_blocking()) {
        return false;
    }

    return true;
}

bool Connection::set_non_blocking() {
    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags == -1) {
        set_error("Failed to get socket flags");
        return false;
    }

    if (fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
        set_error("Failed to set socket to non-blocking mode");
        return false;
    }

    return true;
}

void Connection::cleanup_ssl() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }

    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }

    if (socket_fd_ != -1) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

int Connection::send(const uint8_t* data, size_t length) {
    if (!is_connected()) {
        set_error("Not connected");
        return -1;
    }

    int sent = SSL_write(ssl_, data, length);
    if (sent <= 0) {
        int err = SSL_get_error(ssl_, sent);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            return 0; // Would block, try again later
        }

        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        set_error("SSL write failed: " + std::string(err_buf));
        return -1;
    }

    return sent;
}

int Connection::receive(uint8_t* buffer, size_t max_length) {
    if (!is_connected()) {
        set_error("Not connected");
        return -1;
    }

    int received = SSL_read(ssl_, buffer, max_length);
    if (received <= 0) {
        int err = SSL_get_error(ssl_, received);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; // No data available, non-blocking
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            // Connection closed by peer
            set_error("Connection closed by peer");
            disconnect();
            return -1;
        }

        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        set_error("SSL read failed: " + std::string(err_buf));
        return -1;
    }

    if (on_data_received_) {
        on_data_received_(buffer, received);
    }

    return received;
}

void Connection::set_state(ConnectionState new_state) {
    state_ = new_state;
}

void Connection::set_error(const std::string& error) {
    last_error_ = error;
    if (on_error_) {
        on_error_(error);
    }
}

} // namespace tls
} // namespace fix
} // namespace electronx
