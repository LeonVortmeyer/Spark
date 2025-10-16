#pragma once

#include "../tls/Connection.H"
#include <string>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <vector>

namespace electronx {
namespace fix {
namespace session {

/**
 * @brief Manages a FIX session with sequence numbers, heartbeats, and recovery
 *
 * Implements FIXT.1.1 transport with FIX 5.0 SP2 application layer as required
 * by ElectronX exchange specifications.
 */
class Session {
public:
    enum class SessionType {
        ORDER_ENTRY,    // Order submission, modification, cancellation
        MARKET_DATA,    // Market data subscription and updates
        DROP_COPY       // Read-only execution reports
    };

    enum class SessionState {
        DISCONNECTED,
        CONNECTING,
        LOGON_SENT,
        LOGGED_ON,
        LOGOUT_SENT,
        DISCONNECTING,
        ERROR
    };

    /**
     * @brief Configuration for FIX session
     */
    struct Config {
        // Connection settings
        std::string host;
        uint16_t port;
        std::string client_cert_path;
        std::string client_key_path;
        std::string ca_cert_path;
        SessionType session_type;

        // FIX session parameters
        std::string sender_comp_id;      // Your assigned SenderCompID
        std::string target_comp_id;      // Always "EXI" for ElectronX
        std::string sender_sub_id;       // User email for order entry (Tag 50)
        std::string password;            // Optional session password (Tag 554)

        // Timing settings
        int heartbeat_interval{30};      // Recommended 30 seconds
        int reconnect_interval_ms{60000}; // 60 seconds
        int logon_timeout_ms{30000};

        // Sequence number settings
        bool reset_seq_num_on_logon{true}; // ResetSeqNumFlag (141)

        // Weekly reset schedule (Sunday 06:15 UTC)
        bool enable_weekly_reset{true};
    };

    using OnLogonCallback = std::function<void()>;
    using OnLogoutCallback = std::function<void(const std::string& reason)>;
    using OnMessageCallback = std::function<void(const std::string& msg_type, const std::vector<uint8_t>& message)>;
    using OnErrorCallback = std::function<void(const std::string& error)>;

    explicit Session(const Config& config);
    ~Session();

    // Prevent copying
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    /**
     * @brief Start the session (connect and logon)
     * @return true if started successfully
     */
    bool start();

    /**
     * @brief Stop the session (logout and disconnect)
     */
    void stop();

    /**
     * @brief Process I/O and session management
     * Should be called regularly (e.g., in a processing loop)
     */
    void process();

    /**
     * @brief Send a FIX message
     * @param message FIX message body (without header/trailer)
     * @param msg_type Message type (Tag 35)
     * @return true if sent successfully
     */
    bool send_message(const std::string& msg_type, const std::string& message);

    /**
     * @brief Check if session is logged on and ready
     */
    bool is_logged_on() const { return state_ == SessionState::LOGGED_ON; }

    /**
     * @brief Get current session state
     */
    SessionState get_state() const { return state_; }

    /**
     * @brief Get outbound sequence number
     */
    uint32_t get_outbound_seq_num() const { return outbound_seq_num_; }

    /**
     * @brief Get inbound sequence number
     */
    uint32_t get_inbound_seq_num() const { return inbound_seq_num_; }

    // Callback setters
    void set_on_logon(OnLogonCallback callback) { on_logon_ = callback; }
    void set_on_logout(OnLogoutCallback callback) { on_logout_ = callback; }
    void set_on_message(OnMessageCallback callback) { on_message_ = callback; }
    void set_on_error(OnErrorCallback callback) { on_error_ = callback; }

private:
    /**
     * @brief Send logon message
     */
    bool send_logon();

    /**
     * @brief Send logout message
     */
    bool send_logout(const std::string& text = "");

    /**
     * @brief Send heartbeat message
     */
    bool send_heartbeat(const std::string& test_req_id = "");

    /**
     * @brief Send test request message
     */
    bool send_test_request();

    /**
     * @brief Handle received logon message
     */
    void handle_logon(const std::vector<uint8_t>& message);

    /**
     * @brief Handle received logout message
     */
    void handle_logout(const std::vector<uint8_t>& message);

    /**
     * @brief Handle received heartbeat message
     */
    void handle_heartbeat(const std::vector<uint8_t>& message);

    /**
     * @brief Handle received test request message
     */
    void handle_test_request(const std::vector<uint8_t>& message);

    /**
     * @brief Handle received resend request message
     */
    void handle_resend_request(const std::vector<uint8_t>& message);

    /**
     * @brief Handle received sequence reset message
     */
    void handle_sequence_reset(const std::vector<uint8_t>& message);

    /**
     * @brief Process received data from connection
     */
    void process_received_data();

    /**
     * @brief Process a complete FIX message
     */
    void process_fix_message(const std::vector<uint8_t>& message);

    /**
     * @brief Check heartbeat timing
     */
    void check_heartbeat();

    /**
     * @brief Build FIX message with header and trailer
     */
    std::vector<uint8_t> build_fix_message(const std::string& msg_type, const std::string& body);

    /**
     * @brief Calculate FIX checksum
     */
    std::string calculate_checksum(const std::string& message);

    /**
     * @brief Get current UTC timestamp in FIX format
     */
    std::string get_utc_timestamp();

    /**
     * @brief Parse FIX tag from message
     */
    std::string get_tag_value(const std::vector<uint8_t>& message, int tag);

    /**
     * @brief Check if weekly reset time (Sunday 06:15 UTC)
     */
    bool is_weekly_reset_time();

    /**
     * @brief Reset sequence numbers
     */
    void reset_sequence_numbers();

    /**
     * @brief Update session state
     */
    void set_state(SessionState new_state);

    Config config_;
    SessionState state_{SessionState::DISCONNECTED};

    // TLS connection
    std::unique_ptr<tls::Connection> connection_;

    // Sequence numbers
    std::atomic<uint32_t> outbound_seq_num_{1};
    std::atomic<uint32_t> inbound_seq_num_{1};
    std::mutex seq_num_mutex_;

    // Heartbeat management
    std::chrono::steady_clock::time_point last_sent_time_;
    std::chrono::steady_clock::time_point last_received_time_;
    std::chrono::steady_clock::time_point last_test_request_time_;
    bool test_request_outstanding_{false};

    // Message buffer for incomplete messages
    std::vector<uint8_t> receive_buffer_;

    // Callbacks
    OnLogonCallback on_logon_;
    OnLogoutCallback on_logout_;
    OnMessageCallback on_message_;
    OnErrorCallback on_error_;

    // Constants
    static constexpr char SOH = '\x01';  // FIX field delimiter
    static constexpr const char* BEGIN_STRING = "FIXT.1.1";
    static constexpr const char* DEFAULT_APPL_VER_ID = "9";  // FIX50SP2
};

} // namespace session
} // namespace fix
} // namespace electronx
