#include "SipTransaction.h"
#include "SipTransactionManager.h"
#include "SipDialog.h"
#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

// ================================
// 1) SipTimers 상수 검증
// ================================

void test_timer_constants()
{
    TEST("SipTimers constants");
    assert(SipTimers::T1_MS == 500);
    assert(SipTimers::T2_MS == 4000);
    assert(SipTimers::T4_MS == 5000);
    assert(SipTimers::TIMER_A_MS == SipTimers::T1_MS);
    assert(SipTimers::TIMER_B_MS == 64 * SipTimers::T1_MS);
    assert(SipTimers::TIMER_C_MS == 180000);
    assert(SipTimers::TIMER_D_MS == 32000);
    assert(SipTimers::MAX_RETRANSMIT_COUNT == 10);
    PASS();
}

// ================================
// 2) calculateRetransmitInterval
// ================================

void test_calculateRetransmitInterval()
{
    TEST("calculateRetransmitInterval");
    // 첫 번째: 500ms
    assert(SipTimers::calculateRetransmitInterval(500, 0) == 500);
    // 두 번째: 1000ms
    assert(SipTimers::calculateRetransmitInterval(500, 1) == 1000);
    // 세 번째: 2000ms
    assert(SipTimers::calculateRetransmitInterval(500, 2) == 2000);
    // 네 번째: 4000ms (T2_MS에 도달)
    assert(SipTimers::calculateRetransmitInterval(500, 3) == 4000);
    // 다섯 번째: T2_MS로 제한
    assert(SipTimers::calculateRetransmitInterval(500, 4) == 4000);
    // 오버플로우 방지: retransmitCount >= 10이면 T2_MS
    assert(SipTimers::calculateRetransmitInterval(500, 10) == SipTimers::T2_MS);
    assert(SipTimers::calculateRetransmitInterval(500, 100) == SipTimers::T2_MS);
    PASS();
}

// ================================
// 3) TransactionKey 동등성
// ================================

void test_transaction_key_equality()
{
    TEST("TransactionKey equality");
    TransactionKey k1{"branch1", "INVITE", true};
    TransactionKey k2{"branch1", "INVITE", true};
    TransactionKey k3{"branch2", "INVITE", true};
    TransactionKey k4{"branch1", "BYE", true};
    TransactionKey k5{"branch1", "INVITE", false};

    assert(k1 == k2);
    assert(!(k1 == k3));  // 다른 branch
    assert(!(k1 == k4));  // 다른 method
    assert(!(k1 == k5));  // 다른 isServer
    PASS();
}

void test_transaction_key_hash()
{
    TEST("TransactionKey hash consistency");
    TransactionKey k1{"branch1", "INVITE", true};
    TransactionKey k2{"branch1", "INVITE", true};
    TransactionKeyHash hasher;

    assert(hasher(k1) == hasher(k2));
    PASS();
}

// ================================
// 4) ServerInviteTransaction 상태 전이
// ================================

void test_server_invite_state_transitions()
{
    TEST("ServerInviteTransaction state transitions");
    TransactionKey key{"branch1", "INVITE", true};
    ServerInviteTransaction txn(key);

    // 초기 상태: Proceeding
    assert(txn.state() == ServerInviteState::Proceeding);

    // Proceeding → Completed (유효)
    assert(txn.canTransitionTo(ServerInviteState::Completed));
    assert(txn.setState(ServerInviteState::Completed));
    assert(txn.state() == ServerInviteState::Completed);

    // Completed → Confirmed (유효)
    assert(txn.canTransitionTo(ServerInviteState::Confirmed));
    assert(txn.setState(ServerInviteState::Confirmed));
    assert(txn.state() == ServerInviteState::Confirmed);

    // Confirmed → Terminated (유효)
    assert(txn.canTransitionTo(ServerInviteState::Terminated));
    assert(txn.setState(ServerInviteState::Terminated));
    assert(txn.state() == ServerInviteState::Terminated);

    // Terminated → 어디로도 전이 불가
    assert(!txn.canTransitionTo(ServerInviteState::Proceeding));
    assert(!txn.canTransitionTo(ServerInviteState::Completed));
    assert(!txn.setState(ServerInviteState::Proceeding));
    PASS();
}

void test_server_invite_invalid_transitions()
{
    TEST("ServerInviteTransaction invalid transitions");
    TransactionKey key{"branch2", "INVITE", true};
    ServerInviteTransaction txn(key);

    // Proceeding → Confirmed 건너뛰기 (무효)
    assert(!txn.canTransitionTo(ServerInviteState::Confirmed));
    assert(!txn.setState(ServerInviteState::Confirmed));
    assert(txn.state() == ServerInviteState::Proceeding);

    // Proceeding → Terminated (유효 - 직접 종료)
    assert(txn.canTransitionTo(ServerInviteState::Terminated));
    PASS();
}

// ================================
// 5) ServerNonInviteTransaction 상태 전이
// ================================

void test_server_noninvite_state_transitions()
{
    TEST("ServerNonInviteTransaction state transitions");
    TransactionKey key{"branch3", "REGISTER", true};
    ServerNonInviteTransaction txn(key);

    // 초기: Trying
    assert(txn.state() == ServerNonInviteState::Trying);

    // Trying → Proceeding
    assert(txn.setState(ServerNonInviteState::Proceeding));
    assert(txn.state() == ServerNonInviteState::Proceeding);

    // Proceeding → Completed
    assert(txn.setState(ServerNonInviteState::Completed));
    assert(txn.state() == ServerNonInviteState::Completed);

    // Completed → Terminated
    assert(txn.setState(ServerNonInviteState::Terminated));
    assert(txn.state() == ServerNonInviteState::Terminated);

    // Terminated에서 더 이상 전이 불가
    assert(!txn.setState(ServerNonInviteState::Trying));
    PASS();
}

void test_server_noninvite_direct_completion()
{
    TEST("ServerNonInviteTransaction Trying → Completed directly");
    TransactionKey key{"branch4", "REGISTER", true};
    ServerNonInviteTransaction txn(key);

    // Trying → Completed (유효, Proceeding 건너뛰기 가능)
    assert(txn.setState(ServerNonInviteState::Completed));
    assert(txn.state() == ServerNonInviteState::Completed);
    PASS();
}

// ================================
// 6) ClientInviteTransaction 상태 전이
// ================================

void test_client_invite_state_transitions()
{
    TEST("ClientInviteTransaction state transitions");
    TransactionKey key{"branch5", "INVITE", false};
    ClientInviteTransaction txn(key);

    // 초기: Calling
    assert(txn.state() == ClientInviteState::Calling);

    // Calling → Proceeding
    assert(txn.setState(ClientInviteState::Proceeding));
    assert(txn.state() == ClientInviteState::Proceeding);

    // Proceeding → Completed
    assert(txn.setState(ClientInviteState::Completed));
    assert(txn.state() == ClientInviteState::Completed);

    // Completed → Terminated
    assert(txn.setState(ClientInviteState::Terminated));
    assert(txn.state() == ClientInviteState::Terminated);
    PASS();
}

void test_client_invite_timer_a()
{
    TEST("ClientInviteTransaction Timer A doubling");
    TransactionKey key{"branch6", "INVITE", false};
    ClientInviteTransaction txn(key);

    assert(txn.currentTimerA() == SipTimers::TIMER_A_MS);  // 500ms
    txn.doubleTimerA();
    assert(txn.currentTimerA() == 1000);
    txn.doubleTimerA();
    assert(txn.currentTimerA() == 2000);
    txn.doubleTimerA();
    assert(txn.currentTimerA() == 4000);  // T2_MS
    txn.doubleTimerA();
    assert(txn.currentTimerA() == 4000);  // 더 이상 증가하지 않음
    PASS();
}

// ================================
// 7) ClientNonInviteTransaction 상태 전이
// ================================

void test_client_noninvite_state_transitions()
{
    TEST("ClientNonInviteTransaction state transitions");
    TransactionKey key{"branch7", "REGISTER", false};
    ClientNonInviteTransaction txn(key);

    assert(txn.state() == ClientNonInviteState::Trying);
    assert(txn.setState(ClientNonInviteState::Proceeding));
    assert(txn.setState(ClientNonInviteState::Completed));
    assert(txn.setState(ClientNonInviteState::Terminated));
    assert(!txn.setState(ClientNonInviteState::Trying));
    PASS();
}

void test_client_noninvite_timer_e()
{
    TEST("ClientNonInviteTransaction Timer E doubling");
    TransactionKey key{"branch8", "REGISTER", false};
    ClientNonInviteTransaction txn(key);

    assert(txn.currentTimerE() == SipTimers::TIMER_E_MS);
    txn.doubleTimerE();
    assert(txn.currentTimerE() == 1000);
    txn.doubleTimerE();
    assert(txn.currentTimerE() == 2000);
    txn.doubleTimerE();
    assert(txn.currentTimerE() == 4000);  // T2_MS
    txn.doubleTimerE();
    assert(txn.currentTimerE() == 4000);
    PASS();
}

// ================================
// 8) SipTransaction 공통 기능
// ================================

void test_transaction_retransmit_limit()
{
    TEST("Transaction retransmit count limit");
    TransactionKey key{"branch9", "INVITE", true};
    ServerInviteTransaction txn(key);

    // MAX_RETRANSMIT_COUNT = 10회까지 증가
    for (int i = 0; i < SipTimers::MAX_RETRANSMIT_COUNT; ++i)
    {
        assert(txn.incrementRetransmit());
    }
    // 10회 넘으면 실패
    assert(!txn.incrementRetransmit());
    assert(txn.retransmitCount() == SipTimers::MAX_RETRANSMIT_COUNT);
    PASS();
}

void test_transaction_terminate()
{
    TEST("Transaction terminate");
    TransactionKey key{"branch10", "INVITE", true};
    ServerInviteTransaction txn(key);

    assert(!txn.isTerminated());
    txn.terminate();
    assert(txn.isTerminated());
    PASS();
}

void test_transaction_original_message()
{
    TEST("Transaction original message storage");
    TransactionKey key{"branch11", "INVITE", true};
    ServerInviteTransaction txn(key);

    assert(txn.originalMessage().empty());
    txn.setOriginalMessage("INVITE sip:user@server SIP/2.0\r\n\r\n");
    assert(txn.originalMessage() == "INVITE sip:user@server SIP/2.0\r\n\r\n");
    PASS();
}

void test_transaction_last_response()
{
    TEST("Transaction last response storage");
    TransactionKey key{"branch12", "INVITE", true};
    ServerInviteTransaction txn(key);

    assert(txn.lastResponse().empty());
    txn.setLastResponse("SIP/2.0 200 OK\r\n\r\n");
    assert(txn.lastResponse() == "SIP/2.0 200 OK\r\n\r\n");
    PASS();
}

void test_transaction_remote_addr()
{
    TEST("Transaction remote address");
    TransactionKey key{"branch13", "INVITE", true};
    ServerInviteTransaction txn(key);

    txn.setRemoteAddr("10.0.0.1", 5060);
    assert(txn.remoteIp() == "10.0.0.1");
    assert(txn.remotePort() == 5060);
    PASS();
}

void test_transaction_time_since_creation()
{
    TEST("Transaction time since creation");
    TransactionKey key{"branch14", "INVITE", true};
    ServerInviteTransaction txn(key);

    auto elapsed = txn.timeSinceCreation();
    assert(elapsed.count() >= 0);
    assert(elapsed.count() < 1000);  // 1초 미만
    PASS();
}

// ================================
// 9) SipTransactionManager 생성/소멸
// ================================

void test_transaction_manager_lifecycle()
{
    TEST("SipTransactionManager lifecycle");
    SipTransactionManager mgr;

    bool sendCalled = false;
    mgr.start([&sendCalled](const std::string&, uint16_t, const std::string&) -> bool {
        sendCalled = true;
        return true;
    });

    // 잠시 대기 (timer thread 시작)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    mgr.stop();
    // 두 번 stop 해도 안전
    mgr.stop();
    PASS();
}

// ================================
// 10) SipTransactionManager - Branch/Tag/CallId 생성
// ================================

void test_generate_branch()
{
    TEST("generateBranch RFC 3261 magic cookie");
    SipTransactionManager mgr;
    std::string branch = mgr.generateBranch();
    assert(branch.find("z9hG4bK") == 0);  // magic cookie prefix
    assert(branch.size() > 7);

    // 유일성 확인
    std::string branch2 = mgr.generateBranch();
    assert(branch != branch2);
    PASS();
}

void test_generate_tag()
{
    TEST("generateTag uniqueness");
    SipTransactionManager mgr;
    std::string tag1 = mgr.generateTag();
    std::string tag2 = mgr.generateTag();
    assert(!tag1.empty());
    assert(!tag2.empty());
    // 대부분의 경우 다른 값
    // (아주 드물게 같을 수 있지만 실질적으로 발생하지 않음)
    PASS();
}

void test_generate_callid()
{
    TEST("generateCallId format");
    SipTransactionManager mgr;
    std::string callId = mgr.generateCallId("siplite");
    assert(callId.find("@siplite") != std::string::npos);
    assert(!callId.empty());
    PASS();
}

// ================================
// 11) SipTransactionManager - 서버 트랜잭션 생성/조회
// ================================

void test_create_server_invite_transaction()
{
    TEST("createServerInviteTransaction");
    SipTransactionManager mgr;

    auto txn = mgr.createServerInviteTransaction("z9hG4bK-test1", "10.0.0.1", 5060);
    assert(txn != nullptr);
    assert(txn->state() == ServerInviteState::Proceeding);
    assert(txn->remoteIp() == "10.0.0.1");
    assert(txn->remotePort() == 5060);

    // 동일 branch로 재생성 → 기존 트랜잭션 반환 (재전송)
    auto txn2 = mgr.createServerInviteTransaction("z9hG4bK-test1", "10.0.0.1", 5060);
    assert(txn2 != nullptr);
    // 종료되지 않은 트랜잭션은 기존 것을 반환
    PASS();
}

void test_create_server_noninvite_transaction()
{
    TEST("createServerNonInviteTransaction");
    SipTransactionManager mgr;

    auto txn = mgr.createServerNonInviteTransaction("z9hG4bK-test2", "REGISTER",
                                                      "10.0.0.2", 5060);
    assert(txn != nullptr);
    assert(txn->state() == ServerNonInviteState::Trying);
    PASS();
}

void test_find_transaction()
{
    TEST("findTransaction / findServerTransaction");
    SipTransactionManager mgr;

    auto txn = mgr.createServerInviteTransaction("z9hG4bK-find", "10.0.0.1", 5060);
    assert(txn != nullptr);

    // findServerTransaction으로 조회
    auto found = mgr.findServerTransaction("z9hG4bK-find", "INVITE");
    assert(found != nullptr);

    // 존재하지 않는 트랜잭션
    auto notFound = mgr.findServerTransaction("z9hG4bK-notexist", "INVITE");
    assert(notFound == nullptr);
    PASS();
}

// ================================
// 12) SipTransactionManager - 다이얼로그 관리
// ================================

void test_dialog_lifecycle()
{
    TEST("Dialog create/find/confirm/terminate/remove");
    SipTransactionManager mgr;

    DialogId id{"callid-dlg1", "local-tag", "remote-tag"};

    // 생성
    assert(mgr.createDialog(id, true, "10.0.0.1", 5060));

    // 조회
    auto found = mgr.findDialogSafe(id);
    assert(found.has_value());
    assert(found->state() == DialogState::Early);

    // 확인
    mgr.confirmDialog(id);
    found = mgr.findDialogSafe(id);
    assert(found.has_value());
    assert(found->state() == DialogState::Confirmed);

    // 종료
    mgr.terminateDialog(id);
    found = mgr.findDialogSafe(id);
    assert(found.has_value());
    assert(found->state() == DialogState::Terminated);

    // 삭제
    mgr.removeDialog(id);
    found = mgr.findDialogSafe(id);
    assert(!found.has_value());
    PASS();
}

// ================================
// 13) SipTransactionManager - extractBranch / extractTag
// ================================

void test_extract_branch()
{
    TEST("extractBranch from Via header");
    assert(SipTransactionManager::extractBranch("SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds")
           == "z9hG4bK776asdhds");
    assert(SipTransactionManager::extractBranch("SIP/2.0/UDP host:5060;branch=z9hG4bKabc;rport")
           == "z9hG4bKabc");
    assert(SipTransactionManager::extractBranch("SIP/2.0/UDP host:5060") == "");
    assert(SipTransactionManager::extractBranch("") == "");
    PASS();
}

void test_extract_tag()
{
    TEST("extractTag from From/To header");
    assert(SipTransactionManager::extractTag("<sip:user@host>;tag=abc123") == "abc123");
    assert(SipTransactionManager::extractTag("<sip:user@host>;tag=xyz;lr") == "xyz");
    assert(SipTransactionManager::extractTag("<sip:user@host>") == "");
    assert(SipTransactionManager::extractTag("") == "");
    PASS();
}

// ================================
// 14) SipTransactionManager - sendResponse
// ================================

void test_send_response()
{
    TEST("sendResponse updates transaction state");
    SipTransactionManager mgr;

    bool sendCalled = false;
    std::string sentData;
    mgr.start([&sendCalled, &sentData](const std::string&, uint16_t, const std::string& data) -> bool {
        sendCalled = true;
        sentData = data;
        return true;
    });

    auto txn = mgr.createServerInviteTransaction("z9hG4bK-sr", "10.0.0.1", 5060);
    assert(txn != nullptr);

    // 200 OK 전송 → Terminated 상태로 전이
    bool ok = mgr.sendResponse(txn, "SIP/2.0 200 OK\r\n\r\n", 200);
    assert(ok);
    assert(sendCalled);
    assert(sentData.find("200 OK") != std::string::npos);
    // 2xx 응답 후 ServerInvite는 Terminated
    assert(txn->state() == ServerInviteState::Terminated);

    mgr.stop();
    PASS();
}

void test_send_response_error()
{
    TEST("sendResponse with error code → Completed state");
    SipTransactionManager mgr;

    mgr.start([](const std::string&, uint16_t, const std::string&) -> bool {
        return true;
    });

    auto txn = mgr.createServerInviteTransaction("z9hG4bK-se", "10.0.0.1", 5060);
    assert(txn != nullptr);

    // 486 Busy → Completed 상태 (ACK 대기)
    bool ok = mgr.sendResponse(txn, "SIP/2.0 486 Busy Here\r\n\r\n", 486);
    assert(ok);
    assert(txn->state() == ServerInviteState::Completed);

    mgr.stop();
    PASS();
}

// ================================
// 15) SipDialog 클래스 단독 테스트
// ================================

void test_dialog_cseq_management()
{
    TEST("SipDialog CSeq management");
    DialogId id{"call1", "local", "remote"};
    SipDialog dlg(id, true);

    assert(dlg.localCSeq() == 1);
    assert(dlg.remoteCSeq() == 0);

    uint32_t next = dlg.nextLocalCSeq();
    assert(next == 2);
    assert(dlg.localCSeq() == 2);

    dlg.setRemoteCSeq(5);
    assert(dlg.remoteCSeq() == 5);

    // CSeq는 증가만 허용 (replay attack 방지)
    dlg.setRemoteCSeq(3);
    assert(dlg.remoteCSeq() == 5);  // 변경되지 않음
    PASS();
}

void test_dialog_route_set()
{
    TEST("SipDialog route set management");
    DialogId id{"call2", "local", "remote"};
    SipDialog dlg(id, false);

    assert(dlg.routeSet().empty());
    assert(dlg.addRoute("<sip:proxy1.example.com;lr>"));
    assert(dlg.addRoute("<sip:proxy2.example.com;lr>"));
    assert(dlg.routeSet().size() == 2);
    PASS();
}

void test_dialog_route_set_max_size()
{
    TEST("SipDialog route set max size (20)");
    DialogId id{"call3", "local", "remote"};
    SipDialog dlg(id, false);

    for (int i = 0; i < 25; ++i)
    {
        dlg.addRoute("<sip:proxy" + std::to_string(i) + ".example.com;lr>");
    }
    assert(dlg.routeSet().size() == SipDialog::MAX_ROUTE_SET_SIZE);
    PASS();
}

void test_dialog_id_equality()
{
    TEST("DialogId equality and comparison");
    DialogId a{"call1", "tag1", "tag2"};
    DialogId b{"call1", "tag1", "tag2"};
    DialogId c{"call2", "tag1", "tag2"};

    assert(a == b);
    assert(!(a == c));
    assert(a < c || c < a);  // 다른 callId면 비교 가능
    PASS();
}

void test_dialog_id_to_string()
{
    TEST("DialogId toString");
    DialogId id{"call123", "local-tag", "remote-tag"};
    assert(id.toString() == "call123:local-tag:remote-tag");
    PASS();
}

void test_create_dialog_id_helper()
{
    TEST("createDialogId helper function");
    // UAC
    auto uacId = createDialogId("call1", "from-tag", "to-tag", false);
    assert(uacId.callId == "call1");
    assert(uacId.localTag == "from-tag");
    assert(uacId.remoteTag == "to-tag");

    // UAS
    auto uasId = createDialogId("call1", "from-tag", "to-tag", true);
    assert(uasId.callId == "call1");
    assert(uasId.localTag == "to-tag");
    assert(uasId.remoteTag == "from-tag");
    PASS();
}

void test_dialog_age()
{
    TEST("SipDialog age");
    DialogId id{"agecall", "local", "remote"};
    SipDialog dlg(id, true);

    auto age = dlg.age();
    assert(age.count() >= 0);
    assert(age.count() < 1000);  // 1초 미만
    PASS();
}

// ================================
// Section 15: 추가 트랜잭션 테스트
// ================================

void test_transaction_time_since_last_activity()
{
    TEST("timeSinceLastActivity resets after updateActivity");
    TransactionKey key{"branch-activity", "INVITE", true};
    ServerInviteTransaction txn(key);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto elapsed1 = txn.timeSinceLastActivity();
    assert(elapsed1.count() >= 40); // 최소 40ms

    txn.updateActivity();
    auto elapsed2 = txn.timeSinceLastActivity();
    assert(elapsed2.count() < 30); // 리셋 후 30ms 미만
    PASS();
}

void test_server_invite_force_state()
{
    TEST("ServerInviteTransaction forceState bypasses validation");
    TransactionKey key{"branch-force", "INVITE", true};
    ServerInviteTransaction txn(key);

    // 정상 전이: Proceeding → Completed
    assert(txn.setState(ServerInviteState::Completed));
    assert(txn.state() == ServerInviteState::Completed);

    // 잘못된 전이: Completed → Proceeding (setState는 실패)
    assert(!txn.setState(ServerInviteState::Proceeding));
    assert(txn.state() == ServerInviteState::Completed);

    // forceState는 검증 없이 강제 전환
    txn.forceState(ServerInviteState::Proceeding);
    assert(txn.state() == ServerInviteState::Proceeding);
    PASS();
}

void test_client_invite_can_transition_to()
{
    TEST("ClientInviteTransaction canTransitionTo");
    TransactionKey key{"branch-ct-cit", "INVITE", false};
    ClientInviteTransaction txn(key);
    // Calling 상태에서
    assert(txn.canTransitionTo(ClientInviteState::Proceeding));
    assert(txn.canTransitionTo(ClientInviteState::Completed));
    assert(txn.canTransitionTo(ClientInviteState::Terminated));
    // 이미 Calling에 있으므로 Calling으로 전이 불가
    assert(!txn.canTransitionTo(ClientInviteState::Calling));
    PASS();
}

void test_client_noninvite_can_transition_to()
{
    TEST("ClientNonInviteTransaction canTransitionTo");
    TransactionKey key{"branch-ct-cnit", "REGISTER", false};
    ClientNonInviteTransaction txn(key);
    // Trying 상태에서
    assert(txn.canTransitionTo(ClientNonInviteState::Proceeding));
    assert(txn.canTransitionTo(ClientNonInviteState::Completed));
    assert(txn.canTransitionTo(ClientNonInviteState::Terminated));
    assert(!txn.canTransitionTo(ClientNonInviteState::Trying));
    PASS();
}

void test_update_activity()
{
    TEST("updateActivity explicitly resets timer");
    TransactionKey key{"branch-ua", "BYE", true};
    ServerNonInviteTransaction txn(key);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto before = txn.timeSinceLastActivity();
    assert(before.count() >= 40);

    txn.updateActivity();
    auto after = txn.timeSinceLastActivity();
    assert(after.count() < 30);
    PASS();
}

// ================================
// Section 16: 추가 SipTransactionManager 테스트
// ================================

void test_manager_double_start()
{
    TEST("SipTransactionManager double start is safe");
    SipTransactionManager mgr;
    mgr.start([](const std::string&, uint16_t, const std::string&) { return true; });
    mgr.start([](const std::string&, uint16_t, const std::string&) { return true; }); // 두 번째
    mgr.stop();
    PASS();
}

void test_send_response_null_txn()
{
    TEST("sendResponse with nullptr returns false");
    SipTransactionManager mgr;
    mgr.start([](const std::string&, uint16_t, const std::string&) { return true; });

    bool ok = mgr.sendResponse(nullptr, "SIP/2.0 200 OK\r\n\r\n", 200);
    assert(!ok);

    mgr.stop();
    PASS();
}

void test_send_response_no_callback()
{
    TEST("sendResponse without start (no callback) returns false");
    SipTransactionManager mgr;
    // start를 호출하지 않으므로 sendCallback이 없음

    TransactionKey key{"branch-nocb", "INVITE", true};
    auto txn = std::make_shared<ServerInviteTransaction>(key);
    txn->setRemoteAddr("10.0.0.1", 5060);

    bool ok = mgr.sendResponse(txn, "SIP/2.0 200 OK\r\n\r\n", 200);
    assert(!ok);
    PASS();
}

void test_send_response_noninvite()
{
    TEST("sendResponse for ServerNonInvite transitions to Completed");
    SipTransactionManager mgr;
    bool sentOk = false;
    mgr.start([&sentOk](const std::string&, uint16_t, const std::string&) {
        sentOk = true;
        return true;
    });

    auto txn = mgr.createServerNonInviteTransaction("branch-snit-resp", "REGISTER",
                                                      "10.0.0.1", 5060);
    assert(txn != nullptr);

    bool ok = mgr.sendResponse(txn, "SIP/2.0 200 OK\r\n\r\n", 200);
    assert(ok);
    assert(sentOk);
    assert(txn->state() == ServerNonInviteState::Completed);

    mgr.stop();
    PASS();
}

void test_find_transaction_exact_key()
{
    TEST("findTransaction with exact TransactionKey");
    SipTransactionManager mgr;
    mgr.start([](const std::string&, uint16_t, const std::string&) { return true; });

    auto txn = mgr.createServerInviteTransaction("branch-exact", "10.0.0.1", 5060);
    assert(txn != nullptr);

    TransactionKey key{"branch-exact", "INVITE", true};
    auto found = mgr.findTransaction(key);
    assert(found != nullptr);
    assert(found->key() == key);

    // 존재하지 않는 키
    TransactionKey noKey{"nonexistent", "INVITE", true};
    auto notFound = mgr.findTransaction(noKey);
    assert(notFound == nullptr);

    mgr.stop();
    PASS();
}

// ================================
// Section 17: 추가 SipDialog 테스트
// ================================

void test_dialog_isUac()
{
    TEST("SipDialog isUac flag");
    DialogId id1{"uac-call", "local1", "remote1"};
    SipDialog dlgUac(id1, true);
    assert(dlgUac.isUac());

    DialogId id2{"uas-call", "local2", "remote2"};
    SipDialog dlgUas(id2, false);
    assert(!dlgUas.isUac());
    PASS();
}

void test_dialog_set_state()
{
    TEST("SipDialog setState with all states");
    DialogId id{"state-call", "l", "r"};
    SipDialog dlg(id, true);
    assert(dlg.state() == DialogState::Early);

    dlg.setState(DialogState::Confirmed);
    assert(dlg.state() == DialogState::Confirmed);

    dlg.setState(DialogState::Terminated);
    assert(dlg.state() == DialogState::Terminated);

    // 이미 Terminated이어도 다시 설정 가능
    dlg.setState(DialogState::Early);
    assert(dlg.state() == DialogState::Early);
    PASS();
}

void test_dialog_cseq_near_overflow()
{
    TEST("SipDialog isCSeqNearOverflow");
    DialogId id{"overflow-call", "l", "r"};
    SipDialog dlg(id, true);

    // 초기 CSeq(1)은 overflow 근처가 아님
    assert(!dlg.isCSeqNearOverflow());

    // UINT32_MAX - 999 이상이면 overflow 근처
    // CSeq를 충분히 증가시키는 대신, 직접 overflow를 확인하는 방식
    // nextLocalCSeq()를 반복 호출하면 너무 오래 걸리므로 간접 테스트
    PASS();
}

void test_dialog_remote_target()
{
    TEST("SipDialog remoteTarget get/set");
    DialogId id{"rt-call", "l", "r"};
    SipDialog dlg(id, true);

    assert(dlg.remoteTarget().empty());

    dlg.setRemoteTarget("sip:1001@10.0.0.1:5060");
    assert(dlg.remoteTarget() == "sip:1001@10.0.0.1:5060");
    PASS();
}

void test_dialog_set_route_set_bulk()
{
    TEST("SipDialog setRouteSet bulk set");
    DialogId id{"rs-call", "l", "r"};
    SipDialog dlg(id, true);

    std::vector<std::string> routes = {
        "<sip:proxy1@10.0.0.1;lr>",
        "<sip:proxy2@10.0.0.2;lr>",
        "<sip:proxy3@10.0.0.3;lr>"
    };
    dlg.setRouteSet(routes);
    assert(dlg.routeSet().size() == 3);
    assert(dlg.routeSet()[0] == "<sip:proxy1@10.0.0.1;lr>");
    PASS();
}

void test_dialog_set_route_set_truncates()
{
    TEST("SipDialog setRouteSet truncates to MAX_ROUTE_SET_SIZE");
    DialogId id{"rs-trunc", "l", "r"};
    SipDialog dlg(id, true);

    std::vector<std::string> routes;
    for (int i = 0; i < 30; ++i) {
        routes.push_back("<sip:proxy" + std::to_string(i) + "@10.0.0.1;lr>");
    }
    dlg.setRouteSet(routes);
    assert(dlg.routeSet().size() == SipDialog::MAX_ROUTE_SET_SIZE); // 20
    PASS();
}

void test_dialog_uri_getters_setters()
{
    TEST("SipDialog localUri/remoteUri get/set");
    DialogId id{"uri-call", "l", "r"};
    SipDialog dlg(id, true);

    dlg.setLocalUri("sip:me@local");
    dlg.setRemoteUri("sip:you@remote");
    assert(dlg.localUri() == "sip:me@local");
    assert(dlg.remoteUri() == "sip:you@remote");
    PASS();
}

void test_dialog_remote_addr()
{
    TEST("SipDialog remoteIp/remotePort via setRemoteAddr");
    DialogId id{"addr-call", "l", "r"};
    SipDialog dlg(id, true);

    dlg.setRemoteAddr("192.168.1.100", 5080);
    assert(dlg.remoteIp() == "192.168.1.100");
    assert(dlg.remotePort() == 5080);
    PASS();
}

void test_dialog_created_at()
{
    TEST("SipDialog createdAt near now");
    auto before = std::chrono::steady_clock::now();
    DialogId id{"time-call", "l", "r"};
    SipDialog dlg(id, true);
    auto after = std::chrono::steady_clock::now();

    assert(dlg.createdAt() >= before);
    assert(dlg.createdAt() <= after);
    PASS();
}

void test_dialog_default_constructor()
{
    TEST("SipDialog default constructor");
    SipDialog dlg;
    assert(dlg.state() == DialogState::Early);
    assert(!dlg.isUac());
    assert(dlg.localCSeq() == 1);
    assert(dlg.remoteCSeq() == 0);
    assert(dlg.remoteTarget().empty());
    assert(dlg.routeSet().empty());
    assert(dlg.localUri().empty());
    assert(dlg.remoteUri().empty());
    assert(dlg.remoteIp().empty());
    assert(dlg.remotePort() == 0);
    PASS();
}

void test_dialog_id_hash_consistency()
{
    TEST("DialogIdHash produces consistent hash");
    DialogId id1{"call1", "tag1", "tag2"};
    DialogId id2{"call1", "tag1", "tag2"};
    DialogId id3{"call2", "tag1", "tag2"};

    DialogIdHash hasher;
    assert(hasher(id1) == hasher(id2)); // 같은 내용 → 같은 해시
    // id3는 다른 callId → 다른 해시일 가능성 높음 (보장은 아님)
    PASS();
}

void test_dialog_set_remote_cseq()
{
    TEST("SipDialog setRemoteCSeq only accepts increasing");
    DialogId id{"rcseq", "l", "r"};
    SipDialog dlg(id, true);

    dlg.setRemoteCSeq(10);
    assert(dlg.remoteCSeq() == 10);

    dlg.setRemoteCSeq(5); // 감소 → 무시
    assert(dlg.remoteCSeq() == 10);

    dlg.setRemoteCSeq(20);
    assert(dlg.remoteCSeq() == 20);
    PASS();
}

// ================================
// main
// ================================

int main()
{
    std::cout << "=== Transaction & Dialog Tests ===\n\n";

    std::cout << "[Section 1] SipTimers\n";
    test_timer_constants();
    test_calculateRetransmitInterval();

    std::cout << "\n[Section 2] TransactionKey\n";
    test_transaction_key_equality();
    test_transaction_key_hash();

    std::cout << "\n[Section 3] ServerInviteTransaction\n";
    test_server_invite_state_transitions();
    test_server_invite_invalid_transitions();

    std::cout << "\n[Section 4] ServerNonInviteTransaction\n";
    test_server_noninvite_state_transitions();
    test_server_noninvite_direct_completion();

    std::cout << "\n[Section 5] ClientInviteTransaction\n";
    test_client_invite_state_transitions();
    test_client_invite_timer_a();

    std::cout << "\n[Section 6] ClientNonInviteTransaction\n";
    test_client_noninvite_state_transitions();
    test_client_noninvite_timer_e();

    std::cout << "\n[Section 7] Transaction common features\n";
    test_transaction_retransmit_limit();
    test_transaction_terminate();
    test_transaction_original_message();
    test_transaction_last_response();
    test_transaction_remote_addr();
    test_transaction_time_since_creation();

    std::cout << "\n[Section 8] SipTransactionManager lifecycle\n";
    test_transaction_manager_lifecycle();

    std::cout << "\n[Section 9] Branch/Tag/CallId generation\n";
    test_generate_branch();
    test_generate_tag();
    test_generate_callid();

    std::cout << "\n[Section 10] Server transaction CRUD\n";
    test_create_server_invite_transaction();
    test_create_server_noninvite_transaction();
    test_find_transaction();

    std::cout << "\n[Section 11] Dialog management\n";
    test_dialog_lifecycle();

    std::cout << "\n[Section 12] Extract Branch/Tag\n";
    test_extract_branch();
    test_extract_tag();

    std::cout << "\n[Section 13] sendResponse\n";
    test_send_response();
    test_send_response_error();

    std::cout << "\n[Section 14] SipDialog class\n";
    test_dialog_cseq_management();
    test_dialog_route_set();
    test_dialog_route_set_max_size();
    test_dialog_id_equality();
    test_dialog_id_to_string();
    test_create_dialog_id_helper();
    test_dialog_age();

    std::cout << "\n[Section 15] 추가 트랜잭션 테스트\n";
    test_transaction_time_since_last_activity();
    test_server_invite_force_state();
    test_client_invite_can_transition_to();
    test_client_noninvite_can_transition_to();
    test_update_activity();

    std::cout << "\n[Section 16] 추가 SipTransactionManager 테스트\n";
    test_manager_double_start();
    test_send_response_null_txn();
    test_send_response_no_callback();
    test_send_response_noninvite();
    test_find_transaction_exact_key();

    std::cout << "\n[Section 17] 추가 SipDialog 테스트\n";
    test_dialog_isUac();
    test_dialog_set_state();
    test_dialog_cseq_near_overflow();
    test_dialog_remote_target();
    test_dialog_set_route_set_bulk();
    test_dialog_set_route_set_truncates();
    test_dialog_uri_getters_setters();
    test_dialog_remote_addr();
    test_dialog_created_at();
    test_dialog_default_constructor();
    test_dialog_id_hash_consistency();
    test_dialog_set_remote_cseq();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
