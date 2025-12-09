#pragma once

#include <string>
#include <chrono>
#include <map>
#include <vector>
#include <cstdint>

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
    SipDialog()
        : state_(DialogState::Early)
        , isUac_(false)
        , localCSeq_(1)
        , remoteCSeq_(0)
        , remotePort_(0)
        , createdAt_(std::chrono::steady_clock::now())
    {}
    
    SipDialog(const DialogId& id, bool isUac)
        : id_(id)
        , state_(DialogState::Early)
        , isUac_(isUac)
        , localCSeq_(1)
        , remoteCSeq_(0)
        , remotePort_(0)
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
    // CSeq 증가 (오버플로우 시 1로 wrap around - RFC 3261 허용)
    // 반환값: 새 CSeq, 0이면 오버플로우 발생 (특별 처리 필요)
    uint32_t nextLocalCSeq() 
    { 
        if (localCSeq_ < UINT32_MAX) {
            return ++localCSeq_;
        }
        // 오버플로우: 1로 리셋 (0은 유효하지 않음)
        localCSeq_ = 1;
        return localCSeq_;
    }
    
    // CSeq 오버플로우 체크
    bool isCSeqNearOverflow() const
    {
        return localCSeq_ > (UINT32_MAX - 1000);  // 1000개 여유
    }
    void setRemoteCSeq(uint32_t cseq) 
    { 
        // CSeq는 증가만 허용 (replay attack 방지)
        if (cseq > remoteCSeq_) {
            remoteCSeq_ = cseq;
        }
    }
    
    // 원격 타겟 (Contact 헤더에서 추출)
    const std::string& remoteTarget() const { return remoteTarget_; }
    void setRemoteTarget(const std::string& target) { remoteTarget_ = target; }
    
    // Route Set (Record-Route 헤더들)
    static constexpr std::size_t MAX_ROUTE_SET_SIZE = 20;  // RFC 3261 권장 최대값
    
    const std::vector<std::string>& routeSet() const { return routeSet_; }
    void setRouteSet(const std::vector<std::string>& routes) 
    { 
        // 크기 제한
        if (routes.size() <= MAX_ROUTE_SET_SIZE) {
            routeSet_ = routes;
        } else {
            routeSet_.assign(routes.begin(), routes.begin() + MAX_ROUTE_SET_SIZE);
        }
    }
    bool addRoute(const std::string& route) 
    { 
        if (routeSet_.size() >= MAX_ROUTE_SET_SIZE) {
            return false;  // 최대 개수 초과
        }
        routeSet_.push_back(route); 
        return true;
    }
    
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
    DialogState state_;
    bool isUac_;
    
    uint32_t localCSeq_;
    uint32_t remoteCSeq_;
    
    std::string remoteTarget_;              // Contact URI
    std::vector<std::string> routeSet_;     // Record-Route 헤더들
    
    std::string localUri_;      // From URI (UAC) 또는 To URI (UAS)
    std::string remoteUri_;     // To URI (UAC) 또는 From URI (UAS)
    
    std::string remoteIp_;
    uint16_t remotePort_;
    
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
