#include "Session.H"
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <iostream>

namespace electronx {
namespace fix {
namespace session {

Session::Session(const Config& config)
    : config_(config) {

    // Create TLS connection
    tls::Connection::Config conn_config;
    conn_config.host = config.host;
    conn_config.port = config.port;
    conn_config.client_cert_path = config.client_cert_path;
    conn_config.client_key_path = config.client_key_path;
    conn_config.ca_cert_path = config.ca_cert_path;

    switch (config.session_type) {
        case SessionType::ORDER_ENTRY:
        case SessionType::DROP_COPY:
            conn_config.type = tls::Connection::ConnectionType::ORDER_ENTRY;
            break;
        case SessionType::MARKET_DATA:
            conn_config.type = tls::Connection::ConnectionType::MARKET_DATA;
            break;
    }

    connection_ = std::make_unique<tls::Connection>(conn_config);

    // Set up connection callbacks
    connection_->set_on_connected([this]() {
        std::cout << "TLS connection established, sending logon..." << std::endl;
        send_logon();
    });

    connection_->set_on_disconnected([this]() {
        std::cout << "TLS connection closed" << std::endl;
        set_state(SessionState::DISCONNECTED);
        if (on_logout_) {
            on_logout_("Connection closed");
        }
    });

    connection_->set_on_error([this](const std::string& error) {
        std::cerr << "TLS error: " << error << std::endl;
        if (on_error_) {
            on_error_(error);
        }
    });
}

Session::~Session() {
    stop();
}

bool Session::start() {
    if (state_ != SessionState::DISCONNECTED) {
        return false;
    }

    set_state(SessionState::CONNECTING);

    // Check if weekly reset time and reset sequence numbers if needed
    if (config_.enable_weekly_reset && is_weekly_reset_time()) {
        reset_sequence_numbers();
    }

    if (!connection_->connect()) {
        set_state(SessionState::ERROR);
        return false;
    }

    last_sent_time_ = std::chrono::steady_clock::now();
    last_received_time_ = std::chrono::steady_clock::now();

    return true;
}

void Session::stop() {
    if (state_ == SessionState::LOGGED_ON || state_ == SessionState::LOGON_SENT) {
        send_logout();
    }

    connection_->disconnect();
    set_state(SessionState::DISCONNECTED);
}

void Session::process() {
    if (!connection_->is_connected()) {
        return;
    }

    // Process received data
    process_received_data();

    // Check heartbeat timing
    if (state_ == SessionState::LOGGED_ON) {
        check_heartbeat();
    }
}

void Session::process_received_data() {
    uint8_t buffer[8192];
    int received = connection_->receive(buffer, sizeof(buffer));

    if (received > 0) {
        last_received_time_ = std::chrono::steady_clock::now();

        // Append to receive buffer
        receive_buffer_.insert(receive_buffer_.end(), buffer, buffer + received);

        // Process complete messages
        while (true) {
            // Find message boundaries (8=FIXT.1.1 ... 10=xxx)
            // Look for BeginString tag
            auto begin_pos = std::search(receive_buffer_.begin(), receive_buffer_.end(),
                                        BEGIN_STRING, BEGIN_STRING + std::strlen(BEGIN_STRING));

            if (begin_pos == receive_buffer_.end()) {
                break; // No complete message yet
            }

            // Find checksum field (10=)
            std::string checksum_tag = "10=";
            auto checksum_pos = std::search(begin_pos, receive_buffer_.end(),
                                           checksum_tag.begin(), checksum_tag.end());

            if (checksum_pos == receive_buffer_.end()) {
                break; // No complete message yet
            }

            // Find end of checksum (next SOH after 10=xxx)
            auto end_pos = std::find(checksum_pos, receive_buffer_.end(), SOH);
            if (end_pos == receive_buffer_.end()) {
                break; // Incomplete checksum
            }

            // Extract complete message
            std::vector<uint8_t> message(begin_pos - 2, end_pos + 1); // Include 8= prefix

            // Process the message
            process_fix_message(message);

            // Remove processed message from buffer
            receive_buffer_.erase(receive_buffer_.begin(), end_pos + 1);
        }
    }
}

void Session::process_fix_message(const std::vector<uint8_t>& message) {
    // Extract message type (Tag 35)
    std::string msg_type = get_tag_value(message, 35);

    std::cout << "Received FIX message type: " << msg_type << std::endl;

    // Validate sequence number (Tag 34)
    std::string seq_str = get_tag_value(message, 34);
    if (!seq_str.empty()) {
        uint32_t msg_seq_num = std::stoul(seq_str);
        uint32_t expected = inbound_seq_num_.load();

        if (msg_seq_num > expected) {
            std::cerr << "Gap detected: expected " << expected
                     << ", received " << msg_seq_num << std::endl;
            // TODO: Send ResendRequest
        } else if (msg_seq_num == expected) {
            inbound_seq_num_++;
        }
    }

    // Handle session-level messages
    if (msg_type == "A") {  // Logon
        handle_logon(message);
    } else if (msg_type == "5") {  // Logout
        handle_logout(message);
    } else if (msg_type == "0") {  // Heartbeat
        handle_heartbeat(message);
    } else if (msg_type == "1") {  // Test Request
        handle_test_request(message);
    } else if (msg_type == "2") {  // Resend Request
        handle_resend_request(message);
    } else if (msg_type == "4") {  // Sequence Reset
        handle_sequence_reset(message);
    } else {
        // Application message - pass to callback
        if (on_message_) {
            on_message_(msg_type, message);
        }
    }
}

bool Session::send_logon() {
    set_state(SessionState::LOGON_SENT);

    std::ostringstream body;
    body << "98=0" << SOH;  // EncryptMethod = None
    body << "108=" << config_.heartbeat_interval << SOH;  // HeartBtInt
    body << "1137=" << DEFAULT_APPL_VER_ID << SOH;  // DefaultApplVerID = FIX50SP2

    if (config_.reset_seq_num_on_logon) {
        body << "141=Y" << SOH;  // ResetSeqNumFlag
    }

    if (!config_.password.empty()) {
        body << "554=" << config_.password << SOH;  // Password
    }

    return send_message("A", body.str());
}

bool Session::send_logout(const std::string& text) {
    set_state(SessionState::LOGOUT_SENT);

    std::ostringstream body;
    if (!text.empty()) {
        body << "58=" << text << SOH;  // Text
    }

    return send_message("5", body.str());
}

bool Session::send_heartbeat(const std::string& test_req_id) {
    std::ostringstream body;
    if (!test_req_id.empty()) {
        body << "112=" << test_req_id << SOH;  // TestReqID
    }

    return send_message("0", body.str());
}

bool Session::send_test_request() {
    std::ostringstream body;
    body << "112=" << get_utc_timestamp() << SOH;  // TestReqID

    test_request_outstanding_ = true;
    last_test_request_time_ = std::chrono::steady_clock::now();

    return send_message("1", body.str());
}

bool Session::send_message(const std::string& msg_type, const std::string& body) {
    if (!connection_->is_connected()) {
        return false;
    }

    auto message = build_fix_message(msg_type, body);

    int sent = connection_->send(message.data(), message.size());
    if (sent > 0) {
        last_sent_time_ = std::chrono::steady_clock::now();
        return true;
    }

    return false;
}

std::vector<uint8_t> Session::build_fix_message(const std::string& msg_type, const std::string& body) {
    std::lock_guard<std::mutex> lock(seq_num_mutex_);

    uint32_t seq_num = outbound_seq_num_++;

    std::ostringstream header;
    header << "8=" << BEGIN_STRING << SOH;
    header << "9=";  // BodyLength placeholder

    std::ostringstream msg_body;
    msg_body << "35=" << msg_type << SOH;
    msg_body << "49=" << config_.sender_comp_id << SOH;  // SenderCompID
    msg_body << "56=" << config_.target_comp_id << SOH;  // TargetCompID

    // Add SenderSubID for order-related messages (not on Logon)
    if (msg_type != "A" && !config_.sender_sub_id.empty()) {
        msg_body << "50=" << config_.sender_sub_id << SOH;  // SenderSubID
    }

    msg_body << "34=" << seq_num << SOH;  // MsgSeqNum
    msg_body << "52=" << get_utc_timestamp() << SOH;  // SendingTime
    msg_body << body;

    // Calculate body length
    std::string body_str = msg_body.str();
    header << body_str.length() << SOH;

    // Build complete message without checksum
    std::string message_without_checksum = header.str() + body_str;

    // Calculate and append checksum
    std::string checksum = calculate_checksum(message_without_checksum);
    std::string complete_message = message_without_checksum + "10=" + checksum + SOH;

    return std::vector<uint8_t>(complete_message.begin(), complete_message.end());
}

std::string Session::calculate_checksum(const std::string& message) {
    int sum = 0;
    for (char c : message) {
        sum += static_cast<unsigned char>(c);
    }
    sum %= 256;

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(3) << sum;
    return oss.str();
}

std::string Session::get_utc_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm;
    gmtime_r(&time_t, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d-%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();

    return oss.str();
}

std::string Session::get_tag_value(const std::vector<uint8_t>& message, int tag) {
    std::string tag_str = std::to_string(tag) + "=";

    auto it = std::search(message.begin(), message.end(),
                         tag_str.begin(), tag_str.end());

    if (it == message.end()) {
        return "";
    }

    it += tag_str.length();
    auto end_it = std::find(it, message.end(), SOH);

    return std::string(it, end_it);
}

void Session::handle_logon(const std::vector<uint8_t>& message) {
    std::cout << "Logon acknowledged" << std::endl;
    set_state(SessionState::LOGGED_ON);

    if (on_logon_) {
        on_logon_();
    }
}

void Session::handle_logout(const std::vector<uint8_t>& message) {
    std::string text = get_tag_value(message, 58);
    std::cout << "Logout received: " << text << std::endl;

    if (on_logout_) {
        on_logout_(text);
    }

    stop();
}

void Session::handle_heartbeat(const std::vector<uint8_t>& message) {
    std::string test_req_id = get_tag_value(message, 112);
    if (!test_req_id.empty() && test_request_outstanding_) {
        test_request_outstanding_ = false;
    }
}

void Session::handle_test_request(const std::vector<uint8_t>& message) {
    std::string test_req_id = get_tag_value(message, 112);
    send_heartbeat(test_req_id);
}

void Session::handle_resend_request(const std::vector<uint8_t>& message) {
    // TODO: Implement resend logic
    std::cout << "ResendRequest received - not yet implemented" << std::endl;
}

void Session::handle_sequence_reset(const std::vector<uint8_t>& message) {
    std::string new_seq_str = get_tag_value(message, 36);
    if (!new_seq_str.empty()) {
        uint32_t new_seq = std::stoul(new_seq_str);
        inbound_seq_num_ = new_seq;
        std::cout << "Sequence number reset to " << new_seq << std::endl;
    }
}

void Session::check_heartbeat() {
    auto now = std::chrono::steady_clock::now();
    auto since_last_sent = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_sent_time_).count();
    auto since_last_received = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_received_time_).count();

    // Send heartbeat if we haven't sent anything in heartbeat interval
    if (since_last_sent >= config_.heartbeat_interval) {
        send_heartbeat();
    }

    // Send test request if we haven't received anything
    if (since_last_received >= config_.heartbeat_interval && !test_request_outstanding_) {
        send_test_request();
    }

    // Disconnect if test request not answered
    if (test_request_outstanding_) {
        auto since_test_req = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_test_request_time_).count();
        if (since_test_req >= config_.heartbeat_interval) {
            std::cerr << "TestRequest not answered, disconnecting" << std::endl;
            stop();
        }
    }
}

bool Session::is_weekly_reset_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    gmtime_r(&time_t, &tm);

    // Sunday = 0, check if Sunday at 06:15 UTC
    return (tm.tm_wday == 0 && tm.tm_hour == 6 && tm.tm_min == 15);
}

void Session::reset_sequence_numbers() {
    std::lock_guard<std::mutex> lock(seq_num_mutex_);
    outbound_seq_num_ = 1;
    inbound_seq_num_ = 1;
    std::cout << "Sequence numbers reset to 1" << std::endl;
}

void Session::set_state(SessionState new_state) {
    state_ = new_state;
}

} // namespace session
} // namespace fix
} // namespace electronx
