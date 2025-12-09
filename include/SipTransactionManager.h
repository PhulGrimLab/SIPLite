#pragma once

#include "SipTransaction.h"
#include "SipDialog.h"
#include "SipCore.h"

#include <unordered_map>
#include <map>
#include <mutex>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <random>
#include <sstream>
#include <iomanip>
#include <optional>

// ================================
// 전송 콜백 타입
// ================================

using SendCallback = std::function<bool(const std::string& ip, uint16_t port, const std::string& data)>;

// ================================
// SIP 트랜잭션 매니저
// ================================

class SipTransactionManager 
{
public:
    // 최대 트랜잭션/다이얼로그 개수 (메모리 보호)
    static constexpr std::size_t MAX_TRANSACTIONS = 10000;
    static constexpr std::size_t MAX_DIALOGS = 5000;
    
    SipTransactionManager()
        : running_(false)
        , sipCore_(nullptr)
    {}
    
    ~SipTransactionManager() 
    {
        stop();
    }
    
    // 복사/이동 금지
    SipTransactionManager(const SipTransactionManager&) = delete;
    SipTransactionManager& operator=(const SipTransactionManager&) = delete;
    SipTransactionManager(SipTransactionManager&&) = delete;
    SipTransactionManager& operator=(SipTransactionManager&&) = delete;
    
    // 시작/중지
    void start(SendCallback sendCb) 
    {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true))
        {
            return;  // 이미 실행 중
        }
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            sendCallback_ = sendCb;
        }
        timerThread_ = std::thread(&SipTransactionManager::timerLoop, this);
    }
    
    // SipCore 등록 (만료된 등록/통화 정리용)
    void setSipCore(SipCore* core)
    {
        sipCore_.store(core, std::memory_order_release);
    }
    
    void stop() 
    {
        bool expected = true;
        if (!running_.compare_exchange_strong(expected, false))
        {
            return;  // 이미 중지됨
        }
        if (timerThread_.joinable()) 
        {
            timerThread_.join();
        }
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            sendCallback_ = nullptr;
        }
        // 트랜잭션 정리
        {
            std::lock_guard<std::mutex> lock(txnMutex_);
            transactions_.clear();
        }
        // 다이얼로그 정리
        {
            std::lock_guard<std::mutex> lock(dialogMutex_);
            dialogs_.clear();
        }
    }

    // ================================
    // Branch ID 생성 (RFC 3261 magic cookie)
    // ================================
    
    std::string generateBranch() 
    {
        static const char* magic = "z9hG4bK";  // RFC 3261 magic cookie
        
        static thread_local std::mt19937_64 gen([]() -> std::mt19937_64::result_type {
            std::random_device rd;
            try {
                return static_cast<std::mt19937_64::result_type>(rd());
            } catch (...) {
                // random_device 실패 시 시간 기반 시드 사용
                return static_cast<std::mt19937_64::result_type>(
                    std::chrono::steady_clock::now().time_since_epoch().count() ^
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
            }
        }());
        static thread_local std::uniform_int_distribution<uint64_t> dis;
        
        std::ostringstream oss;
        oss << magic << std::hex << dis(gen);
        return oss.str();
    }
    
    // ================================
    // Tag 생성
    // ================================
    
    std::string generateTag() 
    {
        static thread_local std::mt19937 gen([]() -> std::mt19937::result_type {
            std::random_device rd;
            try {
                return static_cast<std::mt19937::result_type>(rd());
            } catch (...) {
                return static_cast<std::mt19937::result_type>(
                    std::chrono::steady_clock::now().time_since_epoch().count() ^
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
            }
        }());
        static thread_local std::uniform_int_distribution<uint32_t> dis;
        
        std::ostringstream oss;
        oss << std::hex << dis(gen);
        return oss.str();
    }
    
    // ================================
    // Call-ID 생성
    // ================================
    
    std::string generateCallId(const std::string& host = "siplite") 
    {
        static thread_local std::mt19937_64 gen([]() -> std::mt19937_64::result_type {
            std::random_device rd;
            try {
                return static_cast<std::mt19937_64::result_type>(rd());
            } catch (...) {
                return static_cast<std::mt19937_64::result_type>(
                    std::chrono::steady_clock::now().time_since_epoch().count() ^
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
            }
        }());
        static thread_local std::uniform_int_distribution<uint64_t> dis;
        
        std::ostringstream oss;
        oss << std::hex << dis(gen) << "@" << host;
        return oss.str();
    }

    // ================================
    // 서버 트랜잭션 생성/조회
    // ================================
    
    std::shared_ptr<ServerInviteTransaction> createServerInviteTransaction(
        const std::string& branch, 
        const std::string& remoteIp, 
        uint16_t remotePort)
    {
        TransactionKey key{branch, "INVITE", true};
        auto txn = std::make_shared<ServerInviteTransaction>(key);
        txn->setRemoteAddr(remoteIp, remotePort);
        
        std::lock_guard<std::mutex> lock(txnMutex_);
        
        // 트랜잭션 개수 제한 검사
        if (transactions_.size() >= MAX_TRANSACTIONS)
        {
            return nullptr;  // 용량 초과
        }
        
        // 중복 키 처리: 기존 트랜잭션이 종료된 경우에만 교체
        auto it = transactions_.find(key);
        if (it != transactions_.end() && !it->second->isTerminated())
        {
            // 기존 트랜잭션 반환 (재전송된 INVITE)
            return std::dynamic_pointer_cast<ServerInviteTransaction>(it->second);
        }
        transactions_[key] = txn;
        return txn;
    }
    
    std::shared_ptr<ServerNonInviteTransaction> createServerNonInviteTransaction(
        const std::string& branch,
        const std::string& method,
        const std::string& remoteIp,
        uint16_t remotePort)
    {
        TransactionKey key{branch, method, true};
        auto txn = std::make_shared<ServerNonInviteTransaction>(key);
        txn->setRemoteAddr(remoteIp, remotePort);
        
        std::lock_guard<std::mutex> lock(txnMutex_);
        
        // 트랜잭션 개수 제한 검사
        if (transactions_.size() >= MAX_TRANSACTIONS)
        {
            return nullptr;  // 용량 초과
        }
        
        // 중복 키 처리: 기존 트랜잭션이 종료된 경우에만 교체
        auto it = transactions_.find(key);
        if (it != transactions_.end() && !it->second->isTerminated())
        {
            // 기존 트랜잭션 반환 (재전송된 요청)
            return std::dynamic_pointer_cast<ServerNonInviteTransaction>(it->second);
        }
        transactions_[key] = txn;
        return txn;
    }
    
    std::shared_ptr<SipTransaction> findTransaction(const TransactionKey& key) 
    {
        std::lock_guard<std::mutex> lock(txnMutex_);
        auto it = transactions_.find(key);
        if (it != transactions_.end()) 
        {
            return it->second;
        }
        return nullptr;
    }
    
    std::shared_ptr<SipTransaction> findServerTransaction(
        const std::string& branch, 
        const std::string& method)
    {
        TransactionKey key{branch, method, true};
        return findTransaction(key);
    }

    // ================================
    // 다이얼로그 관리
    // ================================
    
    bool createDialog(const DialogId& id, bool isUas,
                      const std::string& remoteIp, uint16_t remotePort)
    {
        SipDialog dialog(id, !isUas);  // isUac = !isUas
        dialog.setRemoteAddr(remoteIp, remotePort);
        
        std::lock_guard<std::mutex> lock(dialogMutex_);
        
        // 다이얼로그 개수 제한 검사
        if (dialogs_.size() >= MAX_DIALOGS)
        {
            return false;  // 용량 초과
        }
        
        dialogs_[id] = dialog;
        return true;
    }
    
    // WARNING: 반환된 포인터는 락 해제 후 무효화될 수 있음
    // 가능하면 findDialogSafe() 사용 권장
    [[deprecated("Use findDialogSafe() instead for thread safety")]]
    SipDialog* findDialog(const DialogId& id) 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        auto it = dialogs_.find(id);
        if (it != dialogs_.end()) 
        {
            return &it->second;
        }
        return nullptr;
    }
    
    // 안전한 버전: 복사본 반환
    std::optional<SipDialog> findDialogSafe(const DialogId& id) 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        auto it = dialogs_.find(id);
        if (it != dialogs_.end()) 
        {
            return it->second;  // 복사본 반환
        }
        return std::nullopt;
    }
    
    void confirmDialog(const DialogId& id) 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        auto it = dialogs_.find(id);
        if (it != dialogs_.end()) 
        {
            it->second.confirm();
        }
    }
    
    void terminateDialog(const DialogId& id) 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        auto it = dialogs_.find(id);
        if (it != dialogs_.end()) 
        {
            it->second.terminate();
        }
    }
    
    void removeDialog(const DialogId& id) 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        dialogs_.erase(id);
    }

    // ================================
    // 응답 전송 및 트랜잭션 상태 업데이트
    // ================================
    
    bool sendResponse(std::shared_ptr<SipTransaction> txn, 
                      const std::string& response,
                      int statusCode)
    {
        if (!txn) return false;
        
        // 콜백 복사본 가져오기
        SendCallback callback;
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            callback = sendCallback_;
        }
        if (!callback) return false;
        
        txn->setLastResponse(response);
        
        bool sent = callback(txn->remoteIp(), txn->remotePort(), response);
        
        if (sent) 
        {
            txn->updateActivity();
            
            // 상태 전이
            if (txn->type() == TransactionType::ServerInvite) 
            {
                auto sitxn = std::dynamic_pointer_cast<ServerInviteTransaction>(txn);
                if (sitxn) 
                {
                    if (statusCode >= 200 && statusCode < 300) 
                    {
                        // 2xx: Terminated (ACK는 다이얼로그 레벨에서 처리)
                        sitxn->setState(ServerInviteState::Terminated);
                    } 
                    else if (statusCode >= 300) 
                    {
                        // 3xx-6xx: Completed, ACK 대기
                        sitxn->setState(ServerInviteState::Completed);
                    }
                }
            } 
            else if (txn->type() == TransactionType::ServerNonInvite) 
            {
                auto snitxn = std::dynamic_pointer_cast<ServerNonInviteTransaction>(txn);
                if (snitxn && statusCode >= 200) 
                {
                    snitxn->setState(ServerNonInviteState::Completed);
                }
            }
        }
        
        return sent;
    }

    // ================================
    // Via 헤더에서 Branch 추출
    // ================================
    
    static std::string extractBranch(const std::string& viaHeader) 
    {
        // 입력 검증
        if (viaHeader.empty() || viaHeader.size() > SipConstants::MAX_HEADER_SIZE)
        {
            return "";
        }
        
        // "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds"
        std::size_t branchPos = viaHeader.find("branch=");
        if (branchPos == std::string::npos) 
        {
            return "";
        }
        
        std::size_t start = branchPos + 7;  // "branch=" 길이
        if (start >= viaHeader.size())
        {
            return "";
        }
        
        std::size_t end = viaHeader.find_first_of(";,\r\n ", start);
        
        std::string branch;
        if (end == std::string::npos) 
        {
            branch = viaHeader.substr(start);
        }
        else
        {
            branch = viaHeader.substr(start, end - start);
        }
        
        // Branch 길이 검증 (합리적인 최대 길이)
        if (branch.size() > 128)
        {
            return "";
        }
        
        return branch;
    }

    // ================================
    // From/To 헤더에서 Tag 추출
    // ================================
    
    static std::string extractTag(const std::string& header) 
    {
        // 입력 검증
        if (header.empty() || header.size() > SipConstants::MAX_HEADER_SIZE)
        {
            return "";
        }
        
        std::size_t tagPos = header.find("tag=");
        if (tagPos == std::string::npos) 
        {
            return "";
        }
        
        std::size_t start = tagPos + 4;
        if (start >= header.size())
        {
            return "";
        }
        
        std::size_t end = header.find_first_of(";,\r\n ", start);
        
        std::string tag;
        if (end == std::string::npos) 
        {
            tag = header.substr(start);
        }
        else
        {
            tag = header.substr(start, end - start);
        }
        
        // Tag 길이 검증 (합리적인 최대 길이)
        if (tag.size() > 128)
        {
            return "";
        }
        
        return tag;
    }

private:
    // ================================
    // 타이머 루프 (재전송 및 타임아웃 처리)
    // ================================
    
    void timerLoop() 
    {
        while (running_) 
        {
            // 100ms 대기 중에도 종료 신호 확인 (10ms 단위)
            for (int i = 0; i < 10 && running_; ++i)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            if (!running_) break;
            
            processTransactionTimers();
            cleanupTerminatedTransactions();
            cleanupTerminatedDialogs();
            
            // SipCore 정리 (만료된 등록 및 미확립 통화)
            SipCore* core = sipCore_.load(std::memory_order_acquire);
            if (core)
            {
                core->cleanupExpiredRegistrations();
                core->cleanupStaleCalls();
            }
        }
    }
    
    void processTransactionTimers() 
    {
        // 재전송 대상 목록을 먼저 수집 (락 범위 최소화)
        struct RetransmitInfo {
            std::string remoteIp;
            uint16_t remotePort;
            std::string response;
            std::weak_ptr<SipTransaction> txnWeak;
        };
        std::vector<RetransmitInfo> retransmitList;
        retransmitList.reserve(32);  // 예상 재전송 수 예약 (재할당 방지)
        
        {
            std::lock_guard<std::mutex> lock(txnMutex_);
            
            for (auto& [key, txn] : transactions_) 
            {
                if (txn->isTerminated()) continue;
                
                auto elapsed = txn->timeSinceLastActivity();
                
                switch (txn->type()) 
                {
                    case TransactionType::ServerInvite:
                    {
                        auto sitxn = std::dynamic_pointer_cast<ServerInviteTransaction>(txn);
                        if (sitxn && sitxn->state() == ServerInviteState::Completed)
                        {
                            // Timer G: 응답 재전송 체크
                            int interval = SipTimers::calculateRetransmitInterval(
                                SipTimers::TIMER_G_MS, txn->retransmitCount());
                            if (elapsed.count() >= interval) 
                            {
                                if (!txn->lastResponse().empty() && txn->incrementRetransmit())
                                {
                                    RetransmitInfo info;
                                    info.remoteIp = txn->remoteIp();
                                    info.remotePort = txn->remotePort();
                                    info.response = txn->lastResponse();
                                    info.txnWeak = txn;
                                    retransmitList.push_back(std::move(info));
                                }
                                else if (txn->retransmitCount() >= SipTimers::MAX_RETRANSMIT_COUNT)
                                {
                                    txn->terminate();
                                }
                            }
                            
                            // Timer H: ACK 대기 타임아웃
                            if (txn->timeSinceCreation().count() >= SipTimers::TIMER_H_MS) 
                            {
                                txn->terminate();
                            }
                        }
                        else if (sitxn && sitxn->state() == ServerInviteState::Confirmed)
                        {
                            // Timer I: 종료 대기
                            if (elapsed.count() >= SipTimers::TIMER_I_MS) 
                            {
                                txn->terminate();
                            }
                        }
                        break;
                    }
                        
                    case TransactionType::ServerNonInvite:
                    {
                        auto snitxn = std::dynamic_pointer_cast<ServerNonInviteTransaction>(txn);
                        if (snitxn && snitxn->state() == ServerNonInviteState::Completed)
                        {
                            // Timer J: 요청 재전송 대기
                            if (elapsed.count() >= SipTimers::TIMER_J_MS) 
                            {
                                txn->terminate();
                            }
                        }
                        break;
                    }
                        
                    default:
                        break;
                }
            }
        }  // txnMutex_ 해제
        
        // 콜백 복사본 캡처 (멀티스레드 안전성)
        SendCallback callback;
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            callback = sendCallback_;
        }
        if (!callback || retransmitList.empty())
        {
            return;
        }
        
        // 락 해제 후 재전송 수행 (데드락 방지)
        for (const auto& info : retransmitList)
        {
            callback(info.remoteIp, info.remotePort, info.response);
            
            // 트랜잭션이 아직 유효하면 activity 업데이트
            if (auto txn = info.txnWeak.lock())
            {
                txn->updateActivity();
            }
        }
    }
    
    void cleanupTerminatedTransactions() 
    {
        std::lock_guard<std::mutex> lock(txnMutex_);
        
        for (auto it = transactions_.begin(); it != transactions_.end(); ) 
        {
            bool shouldRemove = it->second->isTerminated();
            
            // 타임아웃된 트랜잭션도 정리 (Timer B/F: 64초 + 여유 시간)
            if (!shouldRemove)
            {
                auto age = it->second->timeSinceCreation();
                if (age.count() > SipTimers::TIMER_B_MS + 5000)
                {
                    shouldRemove = true;
                }
            }
            
            if (shouldRemove) 
            {
                it = transactions_.erase(it);
            } 
            else 
            {
                ++it;
            }
        }
    }
    
    void cleanupTerminatedDialogs() 
    {
        std::lock_guard<std::mutex> lock(dialogMutex_);
        
        for (auto it = dialogs_.begin(); it != dialogs_.end(); ) 
        {
            auto age = it->second.age();
            bool shouldRemove = false;
            
            if (it->second.state() == DialogState::Terminated)
            {
                // 종료된 지 30초 경과 후 삭제
                if (age.count() > 30000)
                {
                    shouldRemove = true;
                }
            }
            else if (age.count() > static_cast<int64_t>(24) * 60 * 60 * 1000)  // 24시간
            {
                // 오래된 다이얼로그는 먼저 종료 상태로 변경
                it->second.terminate();
                // 다음 클린업 주기에 삭제됨
            }
            
            if (shouldRemove)
            {
                it = dialogs_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

private:
    std::atomic<bool> running_;
    std::thread timerThread_;
    
    mutable std::mutex callbackMutex_;
    SendCallback sendCallback_;
    
    std::mutex txnMutex_;
    std::unordered_map<TransactionKey, std::shared_ptr<SipTransaction>, TransactionKeyHash> transactions_;
    
    std::mutex dialogMutex_;
    std::map<DialogId, SipDialog> dialogs_;
    
    std::atomic<SipCore*> sipCore_;  // 만료된 등록/통화 정리용 (소유권 없음, atomic으로 스레드 안전)
};
