#pragma once

#include <string>
#include <memory>
#include <functional>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace electronx {
namespace fix {
namespace tls {

/**
 * @brief Manages TLS connection with mutual authentication
 *
 * Handles secure connection to ElectronX FIX gateways using mutual TLS.
 * Supports both Order Entry and Market Data gateway connections.
 */
class Connection {
public:
    enum class ConnectionType {
        ORDER_ENTRY,
        MARKET_DATA,
        DROP_COPY
    };

    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        ERROR
    };

    using OnConnectedCallback = std::function<void()>;
    using OnDisconnectedCallback = std::function<void()>;
    using OnDataReceivedCallback = std::function<void(const uint8_t* data, size_t length)>;
    using OnErrorCallback = std::function<void(const std::string& error)>;

    /**
     * @brief Configuration for TLS connection
     */
    struct Config {
        std::string host;
        uint16_t port;
        std::string client_cert_path;     // Client certificate (.crt)
        std::string client_key_path;      // Private key (.key)
        std::string ca_cert_path;         // Certificate authority certificate (.crt)
        ConnectionType type;
        bool use_secondary_ip{false};     // For disaster recovery
        int connect_timeout_ms{30000};
        int socket_timeout_ms{5000};
    };

    explicit Connection(const Config& config);
    ~Connection();

    // Prevent copying
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /**
     * @brief Establish TLS connection to the gateway
     * @return true if connection successful, false otherwise
     */
    bool connect();

    /**
     * @brief Close the TLS connection
     */
    void disconnect();

    /**
     * @brief Send data over the TLS connection
     * @param data Pointer to data buffer
     * @param length Length of data to send
     * @return Number of bytes sent, or -1 on error
     */
    int send(const uint8_t* data, size_t length);

    /**
     * @brief Receive data from the TLS connection (non-blocking)
     * @param buffer Buffer to store received data
     * @param max_length Maximum bytes to receive
     * @return Number of bytes received, 0 if no data, -1 on error
     */
    int receive(uint8_t* buffer, size_t max_length);

    /**
     * @brief Check if connection is active
     */
    bool is_connected() const { return state_ == ConnectionState::CONNECTED; }

    /**
     * @brief Get current connection state
     */
    ConnectionState get_state() const { return state_; }

    /**
     * @brief Get last error message
     */
    std::string get_last_error() const { return last_error_; }

    // Callback setters
    void set_on_connected(OnConnectedCallback callback) { on_connected_ = callback; }
    void set_on_disconnected(OnDisconnectedCallback callback) { on_disconnected_ = callback; }
    void set_on_data_received(OnDataReceivedCallback callback) { on_data_received_ = callback; }
    void set_on_error(OnErrorCallback callback) { on_error_ = callback; }

private:
    /**
     * @brief Initialize OpenSSL context with certificates
     */
    bool init_ssl_context();

    /**
     * @brief Create socket and establish TCP connection
     */
    bool create_socket();

    /**
     * @brief Perform SSL/TLS handshake
     */
    bool ssl_handshake();

    /**
     * @brief Clean up SSL resources
     */
    void cleanup_ssl();

    /**
     * @brief Set socket to non-blocking mode
     */
    bool set_non_blocking();

    /**
     * @brief Update connection state and trigger callbacks
     */
    void set_state(ConnectionState new_state);

    /**
     * @brief Set last error message
     */
    void set_error(const std::string& error);

    Config config_;
    ConnectionState state_{ConnectionState::DISCONNECTED};
    std::string last_error_;

    // OpenSSL structures
    SSL_CTX* ssl_ctx_{nullptr};
    SSL* ssl_{nullptr};
    int socket_fd_{-1};

    // Callbacks
    OnConnectedCallback on_connected_;
    OnDisconnectedCallback on_disconnected_;
    OnDataReceivedCallback on_data_received_;
    OnErrorCallback on_error_;

    // SSL initialization flag
    static bool ssl_initialized_;
    static void init_ssl_library();
    static void cleanup_ssl_library();
};

} // namespace tls
} // namespace fix
} // namespace electronx
