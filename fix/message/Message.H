#ifndef FIX_MESSAGE_H
#define FIX_MESSAGE_H

#include <string>
#include <map>
#include <vector>
#include <optional>
#include <cstdint>

namespace fix {
namespace message {

// FIX Data Types (from ElectronX spec Appendix A)
using Int = int32_t;
using Length = uint32_t;
using SeqNum = uint32_t;
using NumInGroup = uint32_t;
using Float = double;
using Qty = double;
using Price = double;
using Amt = double;
using Char = char;
using Boolean = bool;
using String = std::string;
using Currency = std::string;  // ISO 4217 3-character code
using UTCTimestamp = std::string;  // YYYYMMDD-HH:MM:SS or YYYYMMDD-HH:MM:SS.sss*
using UTCTimeOnly = std::string;   // HH:MM:SS or HH:MM:SS.sss*
using UTCDateOnly = std::string;   // YYYYMMDD
using LocalMktDate = std::string;  // YYYYMMDD

// Standard FIX Tag Numbers (from ElectronX spec)
namespace Tag {
    // Standard Header
    constexpr int BeginString = 8;
    constexpr int BodyLength = 9;
    constexpr int MsgType = 35;
    constexpr int SenderCompID = 49;
    constexpr int TargetCompID = 56;
    constexpr int SenderSubID = 50;
    constexpr int TargetSubID = 57;
    constexpr int MsgSeqNum = 34;
    constexpr int PossDupFlag = 43;
    constexpr int SendingTime = 52;

    // Standard Trailer
    constexpr int Checksum = 10;

    // Session Level
    constexpr int EncryptMethod = 98;
    constexpr int HeartBtInt = 108;
    constexpr int ResetSeqNumFlag = 141;
    constexpr int DefaultApplVerID = 1137;
    constexpr int Password = 554;
    constexpr int TestReqID = 112;
    constexpr int RefSeqNum = 45;
    constexpr int RefTagID = 371;
    constexpr int SessionRejectReason = 373;
    constexpr int Text = 58;
    constexpr int RefMsgType = 372;
    constexpr int BusinessRejectRefID = 379;
    constexpr int BusinessRejectReason = 380;
    constexpr int GapFillFlag = 123;
    constexpr int NewSeqNo = 36;
    constexpr int BeginSeqNo = 7;
    constexpr int EndSeqNo = 16;

    // Order Entry (NewOrderSingle)
    constexpr int ClOrdID = 11;
    constexpr int Account = 1;
    constexpr int ExecInst = 18;
    constexpr int Symbol = 55;
    constexpr int Side = 54;
    constexpr int OrderQty = 38;
    constexpr int OrdType = 40;
    constexpr int Price = 44;
    constexpr int AccountType = 581;
    constexpr int CustOrderCapacity = 582;
    constexpr int NoPartyIDs = 453;
    constexpr int PartyID = 448;
    constexpr int PartyIDSource = 447;
    constexpr int PartyRole = 452;
    constexpr int TimeInForce = 59;
    constexpr int ManualOrderIndicator = 1028;

    // Execution Report
    constexpr int AvgPx = 6;
    constexpr int Commission = 12;
    constexpr int CommType = 13;
    constexpr int CumQty = 14;
    constexpr int ExecID = 17;
    constexpr int SecurityIDSource = 22;
    constexpr int LastPx = 31;
    constexpr int LastQty = 32;
    constexpr int OrderID = 37;
    constexpr int OrdStatus = 39;
    constexpr int OrigClOrdID = 41;
    constexpr int SecurityID = 48;
    constexpr int TransactTime = 60;
    constexpr int OrdRejReason = 103;
    constexpr int SettlCurrAmt = 119;
    constexpr int ExecType = 150;
    constexpr int LeavesQty = 151;
    constexpr int GrossTradeAmt = 381;
    constexpr int TrdType = 828;
    constexpr int TrdMatchID = 880;
    constexpr int AggressorIndicator = 1057;
    constexpr int ExecRestatementReason = 378;
    constexpr int ExecRefID = 19;

    // Order Cancel/Replace
    constexpr int CxlRejReason = 102;
    constexpr int CxlRejResponseTo = 434;

    // Market Data
    constexpr int MDReqID = 262;
    constexpr int SubscriptionRequestType = 263;
    constexpr int MarketDepth = 264;
    constexpr int NoMDEntryTypes = 267;
    constexpr int MDEntryType = 269;
    constexpr int NoRelatedSym = 146;
    constexpr int NoMDEntries = 268;
    constexpr int MDEntryPx = 270;
    constexpr int MDEntrySize = 271;
    constexpr int MDEntryDate = 272;
    constexpr int MDEntryTime = 273;
    constexpr int MDEntryID = 278;
    constexpr int MDUpdateAction = 279;
    constexpr int CorporateAction = 292;
    constexpr int TradingSessionID = 336;
    constexpr int SecurityGroup = 1151;
    constexpr int MDQuoteType = 1070;
    constexpr int ExpireTime = 126;
    constexpr int TradeID = 1003;
    constexpr int AggressorSide = 2446;

    // Security List
    constexpr int SecurityReqID = 320;
    constexpr int SecurityResponseID = 322;
    constexpr int SecurityListRequestType = 559;
    constexpr int SecurityRequestResult = 560;
    constexpr int SecurityType = 167;
    constexpr int Product = 460;
    constexpr int ContractMultiplier = 231;
    constexpr int NoEvents = 864;
    constexpr int EventType = 865;
    constexpr int EventDate = 866;
    constexpr int EventText = 868;
    constexpr int MinPriceIncrement = 969;
    constexpr int MinTradeVol = 562;
    constexpr int PriceLimitType = 1306;
    constexpr int LowLimitPrice = 1148;
    constexpr int HighLimitPrice = 1149;
    constexpr int Currency = 15;
    constexpr int NoLegs = 555;
    constexpr int LegSecurityID = 602;
    constexpr int LegSecurityIDSource = 603;
    constexpr int LegSecurityType = 609;
    constexpr int LegMaturityDate = 611;
    constexpr int LegSide = 624;
    constexpr int LegRatioQty = 623;
}

// Message Types (from ElectronX spec)
namespace MsgType {
    constexpr const char* Heartbeat = "0";
    constexpr const char* TestRequest = "1";
    constexpr const char* ResendRequest = "2";
    constexpr const char* Reject = "3";
    constexpr const char* SequenceReset = "4";
    constexpr const char* Logout = "5";
    constexpr const char* Logon = "A";
    constexpr const char* NewOrderSingle = "D";
    constexpr const char* OrderCancelRequest = "F";
    constexpr const char* OrderCancelReplaceRequest = "G";
    constexpr const char* ExecutionReport = "8";
    constexpr const char* OrderCancelReject = "9";
    constexpr const char* BusinessMessageReject = "j";
    constexpr const char* MarketDataRequest = "V";
    constexpr const char* MarketDataSnapshotFullRefresh = "W";
    constexpr const char* MarketDataIncrementalRefresh = "X";
    constexpr const char* SecurityListRequest = "x";
    constexpr const char* SecurityList = "y";
}

// FIX Field Value Enumerations (from ElectronX spec)
namespace OrdType {
    constexpr char Limit = '2';
}

namespace Side {
    constexpr char Buy = '1';
    constexpr char Sell = '2';
}

namespace TimeInForce {
    constexpr char Day = '0';
    constexpr char GoodTillCancel = '1';
    constexpr char ImmediateOrCancel = '3';
    constexpr char FillOrKill = '4';
}

namespace ExecInst {
    constexpr char ParticipateDoNotInitiate = '6';
    constexpr char BestLimit = 'R';
    constexpr char ImmediatelyExecutableLimit = 'T';
}

namespace OrdStatus {
    constexpr char New = '0';
    constexpr char PartiallyFilled = '1';
    constexpr char Filled = '2';
    constexpr char DoneForDay = '3';
    constexpr char Canceled = '4';
    constexpr char PendingCancel = '6';
    constexpr char Rejected = '8';
    constexpr char PendingNew = 'A';
    constexpr char Expired = 'C';
    constexpr char PendingReplace = 'E';
}

namespace ExecType {
    constexpr char New = '0';
    constexpr char Canceled = '4';
    constexpr char Replaced = '5';
    constexpr char Rejected = '8';
    constexpr char PendingNew = 'A';
    constexpr char Expired = 'C';
    constexpr char PendingReplace = 'E';
    constexpr char Trade = 'F';
    constexpr char TradeCancel = 'H';
}

namespace MDEntryType {
    constexpr char Bid = '0';
    constexpr char Offer = '1';
    constexpr char Trade = '2';
    constexpr char OpeningPrice = '4';
    constexpr char ClosingPrice = '5';
    constexpr char SettlementPrice = '6';
    constexpr char TradingSessionHighPrice = '7';
    constexpr char TradingSessionLowPrice = '8';
    constexpr char TradeVolume = 'B';
    constexpr char OpenInterest = 'C';
    constexpr char TradingReferencePrice = 'g';
}

namespace MDUpdateAction {
    constexpr char New = '0';
    constexpr char Change = '1';
    constexpr char Delete = '2';
}

namespace SubscriptionRequestType {
    constexpr char Snapshot = '0';
    constexpr char SnapshotPlusUpdates = '1';
    constexpr char Unsubscribe = '2';
}

// FIX Field representation
struct Field {
    int tag;
    std::string value;

    Field() : tag(0) {}
    Field(int t, const std::string& v) : tag(t), value(v) {}
    Field(int t, const char* v) : tag(t), value(v) {}
    Field(int t, int v) : tag(t), value(std::to_string(v)) {}
    Field(int t, double v) : tag(t), value(std::to_string(v)) {}
    Field(int t, char v) : tag(t), value(1, v) {}
    Field(int t, bool v) : tag(t), value(v ? "Y" : "N") {}
};

// Repeating Group representation
struct RepeatingGroup {
    int count_tag;  // e.g., NoPartyIDs
    std::vector<std::vector<Field>> entries;  // Each entry is a set of fields

    RepeatingGroup(int tag) : count_tag(tag) {}

    void add_entry(const std::vector<Field>& entry) {
        entries.push_back(entry);
    }

    size_t size() const { return entries.size(); }
};

// Main FIX Message class
class Message {
public:
    Message();
    explicit Message(const std::string& msg_type);
    ~Message();

    // Header fields
    void set_msg_type(const std::string& msg_type);
    void set_sender_comp_id(const std::string& sender);
    void set_target_comp_id(const std::string& target);
    void set_sender_sub_id(const std::string& sub_id);
    void set_msg_seq_num(uint32_t seq_num);
    void set_sending_time(const std::string& time);
    void set_poss_dup_flag(bool flag);

    // Field operations
    void set_field(int tag, const std::string& value);
    void set_field(int tag, int value);
    void set_field(int tag, double value);
    void set_field(int tag, char value);
    void set_field(int tag, bool value);

    std::optional<std::string> get_field(int tag) const;
    std::optional<int> get_int_field(int tag) const;
    std::optional<double> get_double_field(int tag) const;
    std::optional<char> get_char_field(int tag) const;
    std::optional<bool> get_bool_field(int tag) const;

    bool has_field(int tag) const;
    void remove_field(int tag);

    // Repeating group operations
    void add_repeating_group(const RepeatingGroup& group);
    std::optional<RepeatingGroup> get_repeating_group(int count_tag) const;

    // Message serialization/parsing
    std::string to_fix_string() const;
    static Message from_fix_string(const std::string& fix_msg);

    // Getters
    std::string get_msg_type() const;
    uint32_t get_msg_seq_num() const;

    // Validation
    bool validate() const;

private:
    std::string calculate_checksum(const std::string& msg) const;
    std::string get_current_utc_timestamp() const;

    std::map<int, std::string> fields_;
    std::map<int, RepeatingGroup> repeating_groups_;

    // Standard header fields
    std::string msg_type_;
    std::string sender_comp_id_;
    std::string target_comp_id_;
    std::optional<std::string> sender_sub_id_;
    uint32_t msg_seq_num_;
    std::string sending_time_;
    bool poss_dup_flag_;
};

// Helper functions for creating specific message types
Message create_logon_message(const std::string& sender, const std::string& target,
                             int heartbeat_interval, uint32_t seq_num);
Message create_logout_message(const std::string& sender, const std::string& target,
                              uint32_t seq_num, const std::string& text = "");
Message create_heartbeat_message(const std::string& sender, const std::string& target,
                                 uint32_t seq_num, const std::string& test_req_id = "");
Message create_test_request_message(const std::string& sender, const std::string& target,
                                    uint32_t seq_num, const std::string& test_req_id);
Message create_new_order_message(const std::string& sender, const std::string& target,
                                 const std::string& sender_sub_id, uint32_t seq_num,
                                 const std::string& cl_ord_id, const std::string& symbol,
                                 char side, double quantity, double price,
                                 const std::string& account, int cust_order_capacity);
Message create_order_cancel_request(const std::string& sender, const std::string& target,
                                    const std::string& sender_sub_id, uint32_t seq_num,
                                    const std::string& cl_ord_id, const std::string& orig_cl_ord_id,
                                    const std::string& symbol);

} // namespace message
} // namespace fix

#endif // FIX_MESSAGE_H
