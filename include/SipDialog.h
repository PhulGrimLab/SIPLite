#pragma once

#include <string>
#include <chrono>
#include <map>

// ================================
// SIP 다이얼로그 상태 (RFC 3261)
// ================================

enum class DialogState 
{
    Early,          // 1xx 응답 수신 (INVITE에 대한)
    Confirmed,      // 2xx 응답 수신 (세션 확립)
    Terminated      // BYE 또는 오류로 종료
};

// ================================
// SIP 다이얼로그
// ================================

struct DialogId 
{
    std::string callId;
    std::string localTag;    // From-tag (UAC) 또는 To-tag (UAS)
    std::string remoteTag;   // To-tag (UAC) 또는 From-tag (UAS)
    
    bool operator==(const DialogId& other) const 
    {
        return callId == other.callId && 
               localTag == other.localTag && 
               remoteTag == other.remoteTag;
    }
    
    bool operator<(const DialogId& other) const 
    {
        if (callId != other.callId) return callId < other.callId;
        if (localTag != other.localTag) return localTag < other.localTag;
        return remoteTag < other.remoteTag;
    }
    
    std::string toString() const 
    {
        return callId + ":" + localTag + ":" + remoteTag;
    }
};

// DialogId 해시 함수
struct DialogIdHash 
{
    std::size_t operator()(const DialogId& id) const 
    {
        std::size_t h1 = std::hash<std::string>{}(id.callId);
        std::size_t h2 = std::hash<std::string>{}(id.localTag);
        std::size_t h3 = std::hash<std::string>{}(id.remoteTag);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

// ================================
// SIP 다이얼로그 클래스
// ================================

class SipDialog 
{
public:
    SipDialog() = default;
    
    SipDialog(const DialogId& id, bool isUac)
        : id_(id)
        , state_(DialogState::Early)
        , isUac_(isUac)
        , localCSeq_(1)
        , remoteCSeq_(0)
        , createdAt_(std::chrono::steady_clock::now())
    {}
    
    // 복사/이동 허용
    SipDialog(const SipDialog&) = default;
    SipDialog& operator=(const SipDialog&) = default;
    SipDialog(SipDialog&&) = default;
    SipDialog& operator=(SipDialog&&) = default;
    
    // 접근자
    const DialogId& id() const { return id_; }
    DialogState state() const { return state_; }
    bool isUac() const { return isUac_; }
    
    // 상태 설정
    void setState(DialogState newState) { state_ = newState; }
    void confirm() { state_ = DialogState::Confirmed; }
    void terminate() { state_ = DialogState::Terminated; }
    
    // CSeq 관리
    uint32_t localCSeq() const { return localCSeq_; }
    uint32_t remoteCSeq() const { return remoteCSeq_; }
    uint32_t nextLocalCSeq() { return ++localCSeq_; }
    void setRemoteCSeq(uint32_t cseq) { remoteCSeq_ = cseq; }
    
    // 원격 타겟 (Contact 헤더에서 추출)
    const std::string& remoteTarget() const { return remoteTarget_; }
    void setRemoteTarget(const std::string& target) { remoteTarget_ = target; }
    
    // Route Set (Record-Route 헤더들)
    const std::vector<std::string>& routeSet() const { return routeSet_; }
    void setRouteSet(const std::vector<std::string>& routes) { routeSet_ = routes; }
    void addRoute(const std::string& route) { routeSet_.push_back(route); }
    
    // 로컬/원격 URI
    const std::string& localUri() const { return localUri_; }
    const std::string& remoteUri() const { return remoteUri_; }
    void setLocalUri(const std::string& uri) { localUri_ = uri; }
    void setRemoteUri(const std::string& uri) { remoteUri_ = uri; }
    
    // 원격 주소 (실제 UDP 송신용)
    const std::string& remoteIp() const { return remoteIp_; }
    uint16_t remotePort() const { return remotePort_; }
    void setRemoteAddr(const std::string& ip, uint16_t port) 
    { 
        remoteIp_ = ip; 
        remotePort_ = port; 
    }
    
    // 시간 관련
    std::chrono::steady_clock::time_point createdAt() const { return createdAt_; }
    
    std::chrono::milliseconds age() const 
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - createdAt_);
    }

private:
    DialogId id_;
    DialogState state_ = DialogState::Early;
    bool isUac_ = false;    // true: 클라이언트, false: 서버
    
    uint32_t localCSeq_ = 1;
    uint32_t remoteCSeq_ = 0;
    
    std::string remoteTarget_;              // Contact URI
    std::vector<std::string> routeSet_;     // Record-Route 헤더들
    
    std::string localUri_;      // From URI (UAC) 또는 To URI (UAS)
    std::string remoteUri_;     // To URI (UAC) 또는 From URI (UAS)
    
    std::string remoteIp_;
    uint16_t remotePort_ = 0;
    
    std::chrono::steady_clock::time_point createdAt_;
};

// ================================
// 다이얼로그 매칭 헬퍼
// ================================

inline DialogId createDialogId(const std::string& callId,
                                const std::string& fromTag,
                                const std::string& toTag,
                                bool isUas)
{
    DialogId id;
    id.callId = callId;
    if (isUas) 
    {
        // UAS: local = To-tag, remote = From-tag
        id.localTag = toTag;
        id.remoteTag = fromTag;
    } 
    else 
    {
        // UAC: local = From-tag, remote = To-tag
        id.localTag = fromTag;
        id.remoteTag = toTag;
    }
    return id;
}
