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
    SipTransactionManager()
        : running_(false)
    {}
    
    ~SipTransactionManager() 
    {
        stop();
    }
    
    // 복사/이동 금지
    SipTransactionManager(const SipTransactionManager&) = delete;
    SipTransactionManager& operator=(const SipTransactionManager&) = delete;
    
    // 시작/중지
    void start(SendCallback sendCb) 
    {
        sendCallback_ = sendCb;
        running_ = true;
        timerThread_ = std::thread(&SipTransactionManager::timerLoop, this);
    }
    
    void stop() 
    {
        running_ = false;
        if (timerThread_.joinable()) 
        {
            timerThread_.join();
        }
    }

    // ================================
    // Branch ID 생성 (RFC 3261 magic cookie)
    // ================================
    
    std::string generateBranch() 
    {
        static const char* magic = "z9hG4bK";  // RFC 3261 magic cookie
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        
        std::ostringstream oss;
        oss << magic << std::hex << dis(gen);
        return oss.str();
    }
    
    // ================================
    // Tag 생성
    // ================================
    
    std::string generateTag() 
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis;
        
        std::ostringstream oss;
        oss << std::hex << dis(gen);
        return oss.str();
    }
    
    // ================================
    // Call-ID 생성
    // ================================
    
    std::string generateCallId(const std::string& host = "siplite") 
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        
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
    
    void createDialog(const DialogId& id, bool isUas,
                      const std::string& remoteIp, uint16_t remotePort)
    {
        SipDialog dialog(id, !isUas);  // isUac = !isUas
        dialog.setRemoteAddr(remoteIp, remotePort);
        
        std::lock_guard<std::mutex> lock(dialogMutex_);
        dialogs_[id] = dialog;
    }
    
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
        if (!txn || !sendCallback_) return false;
        
        txn->setLastResponse(response);
        
        bool sent = sendCallback_(txn->remoteIp(), txn->remotePort(), response);
        
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
        // "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds"
        std::size_t branchPos = viaHeader.find("branch=");
        if (branchPos == std::string::npos) 
        {
            return "";
        }
        
        std::size_t start = branchPos + 7;  // "branch=" 길이
        std::size_t end = viaHeader.find_first_of(";,\r\n ", start);
        
        if (end == std::string::npos) 
        {
            return viaHeader.substr(start);
        }
        return viaHeader.substr(start, end - start);
    }

    // ================================
    // From/To 헤더에서 Tag 추출
    // ================================
    
    static std::string extractTag(const std::string& header) 
    {
        std::size_t tagPos = header.find("tag=");
        if (tagPos == std::string::npos) 
        {
            return "";
        }
        
        std::size_t start = tagPos + 4;
        std::size_t end = header.find_first_of(";,\r\n ", start);
        
        if (end == std::string::npos) 
        {
            return header.substr(start);
        }
        return header.substr(start, end - start);
    }

private:
    // ================================
    // 타이머 루프 (재전송 및 타임아웃 처리)
    // ================================
    
    void timerLoop() 
    {
        while (running_) 
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            processTransactionTimers();
            cleanupTerminatedTransactions();
            cleanupTerminatedDialogs();
        }
    }
    
    void processTransactionTimers() 
    {
        std::lock_guard<std::mutex> lock(txnMutex_);
        
        for (auto& [key, txn] : transactions_) 
        {
            if (txn->isTerminated()) continue;
            
            auto elapsed = txn->timeSinceLastActivity();
            
            switch (txn->type()) 
            {
                case TransactionType::ServerInvite:
                    processServerInviteTimer(
                        std::dynamic_pointer_cast<ServerInviteTransaction>(txn),
                        elapsed);
                    break;
                    
                case TransactionType::ServerNonInvite:
                    processServerNonInviteTimer(
                        std::dynamic_pointer_cast<ServerNonInviteTransaction>(txn),
                        elapsed);
                    break;
                    
                default:
                    break;
            }
        }
    }
    
    void processServerInviteTimer(std::shared_ptr<ServerInviteTransaction> txn,
                                   std::chrono::milliseconds elapsed)
    {
        if (!txn) return;
        
        switch (txn->state()) 
        {
            case ServerInviteState::Completed:
                // Timer G: 응답 재전송
                if (elapsed.count() >= SipTimers::TIMER_G_MS * (1 << txn->retransmitCount())) 
                {
                    if (!txn->lastResponse().empty() && sendCallback_) 
                    {
                        sendCallback_(txn->remoteIp(), txn->remotePort(), 
                                     txn->lastResponse());
                        txn->incrementRetransmit();
                        txn->updateActivity();
                    }
                }
                
                // Timer H: ACK 대기 타임아웃
                if (txn->timeSinceCreation().count() >= SipTimers::TIMER_H_MS) 
                {
                    txn->terminate();
                }
                break;
                
            case ServerInviteState::Confirmed:
                // Timer I: 종료 대기
                if (elapsed.count() >= SipTimers::TIMER_I_MS) 
                {
                    txn->terminate();
                }
                break;
                
            default:
                break;
        }
    }
    
    void processServerNonInviteTimer(std::shared_ptr<ServerNonInviteTransaction> txn,
                                      std::chrono::milliseconds elapsed)
    {
        if (!txn) return;
        
        switch (txn->state()) 
        {
            case ServerNonInviteState::Completed:
                // Timer J: 요청 재전송 대기
                if (elapsed.count() >= SipTimers::TIMER_J_MS) 
                {
                    txn->terminate();
                }
                break;
                
            default:
                break;
        }
    }
    
    void cleanupTerminatedTransactions() 
    {
        std::lock_guard<std::mutex> lock(txnMutex_);
        
        for (auto it = transactions_.begin(); it != transactions_.end(); ) 
        {
            if (it->second->isTerminated()) 
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
            if (it->second.state() == DialogState::Terminated) 
            {
                // 종료된 지 일정 시간 경과 후 삭제
                if (it->second.age().count() > 30000) // 30초
                {
                    it = dialogs_.erase(it);
                    continue;
                }
            }
            ++it;
        }
    }

private:
    std::atomic<bool> running_;
    std::thread timerThread_;
    SendCallback sendCallback_;
    
    std::mutex txnMutex_;
    std::unordered_map<TransactionKey, std::shared_ptr<SipTransaction>, TransactionKeyHash> transactions_;
    
    std::mutex dialogMutex_;
    std::map<DialogId, SipDialog> dialogs_;
};
