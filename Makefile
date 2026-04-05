# 컴파일러 설정
CXX = g++
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
CXXFLAGS = -Wall -Wextra -std=c++17 -g -I./include -pthread $(OPENSSL_CFLAGS)
LDFLAGS = -pthread $(OPENSSL_LIBS)
SANITIZER_COMMON_FLAGS = -O1 -fno-omit-frame-pointer
ASAN_UBSAN_FLAGS = $(SANITIZER_COMMON_FLAGS) -fsanitize=address,undefined
TSAN_FLAGS = $(SANITIZER_COMMON_FLAGS) -fsanitize=thread
ASAN_ENV = ASAN_OPTIONS=detect_leaks=0:check_initialization_order=1:strict_string_checks=1
UBSAN_ENV = UBSAN_OPTIONS=print_stacktrace=1
TSAN_ENV = TSAN_OPTIONS=halt_on_error=1:history_size=7

ifeq ($(wildcard /usr/include/openssl/err.h),)
$(error OpenSSL development headers not found. Install libssl-dev, then rebuild)
endif

# 디렉토리 설정
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/my_siplite
ASAN_BUILD_DIR = build-asan
TSAN_BUILD_DIR = build-tsan

# 소스 파일 찾기
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))
# 라이브러리 오브젝트 (실제 바이너리의 main을 제외)
LIB_OBJS = $(filter-out $(BUILD_DIR)/main.o, $(OBJS))

# 테스트 바이너리
TEST_DIR = tests
TEST_SRCS = $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJS = $(patsubst $(TEST_DIR)/%.cpp, $(BUILD_DIR)/test_%.o, $(TEST_SRCS))
TEST_TARGET = $(BUILD_DIR)/test_parser

# Additional test targets
TEST_UTIL_TARGET = $(BUILD_DIR)/test_utils

# Extended test targets
TEST_PARSER_EXT_TARGET = $(BUILD_DIR)/test_parser_extended
TEST_UTILS_EXT_TARGET = $(BUILD_DIR)/test_utils_extended
TEST_SIPCORE_EXT_TARGET = $(BUILD_DIR)/test_sipcore_extended
TEST_TRANSACTION_TARGET = $(BUILD_DIR)/test_transaction
TEST_XMLCONFIG_TARGET = $(BUILD_DIR)/test_xmlconfig
TEST_CONCURRENT_QUEUE_TARGET = $(BUILD_DIR)/test_concurrent_queue
TEST_LOGGER_TARGET = $(BUILD_DIR)/test_logger

# 기본 타겟
all: $(BUILD_DIR) $(TARGET)

# 빌드 디렉토리 생성
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 실행 파일 링크
$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Parser test binary (link only parser test object to avoid multiple mains)
$(TEST_TARGET): $(BUILD_DIR)/test_test_parser.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Utils test binary (link only utils test object)
$(TEST_UTIL_TARGET): $(BUILD_DIR)/test_test_utils.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# SipCore test binary
TEST_SIPCORE_TARGET = $(BUILD_DIR)/test_sipcore

TEST_SIPCORE_OBJ = $(BUILD_DIR)/test_test_sipcore.o

$(TEST_SIPCORE_TARGET): $(TEST_SIPCORE_OBJ) $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Extended parser test binary
$(TEST_PARSER_EXT_TARGET): $(BUILD_DIR)/test_test_parser_extended.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Extended utils test binary
$(TEST_UTILS_EXT_TARGET): $(BUILD_DIR)/test_test_utils_extended.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Extended sipcore test binary
$(TEST_SIPCORE_EXT_TARGET): $(BUILD_DIR)/test_test_sipcore_extended.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Transaction/Dialog test binary
$(TEST_TRANSACTION_TARGET): $(BUILD_DIR)/test_test_transaction.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# XmlConfigLoader test binary
$(TEST_XMLCONFIG_TARGET): $(BUILD_DIR)/test_test_xmlconfig.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# ConcurrentQueue test binary
$(TEST_CONCURRENT_QUEUE_TARGET): $(BUILD_DIR)/test_test_concurrent_queue.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# Logger test binary
$(TEST_LOGGER_TARGET): $(BUILD_DIR)/test_test_logger.o $(LIB_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# 오브젝트 파일 컴파일
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 테스트 오브젝트 파일 컴파일
$(BUILD_DIR)/test_%.o: $(TEST_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 클린업
clean:
	rm -rf $(BUILD_DIR)

# 재빌드
rebuild: clean all

# 디버그 정보 추가
debug: CXXFLAGS += -DDEBUG -O0
debug: all

# 릴리즈 빌드
release: CXXFLAGS += -O2 -DNDEBUG
release: LDFLAGS += -s -pthread
release: all

# 실행
run: run_tls

run_plain: all
	./$(TARGET)

run_tls: all
	./scripts/start_tls.sh

# Run parser tests
test: $(TEST_TARGET)
	$(TEST_TARGET)

# Run utils tests
test_utils: $(TEST_UTIL_TARGET)
	$(TEST_UTIL_TARGET)
# Run sipcore tests
test_sipcore: $(TEST_SIPCORE_TARGET)
	$(TEST_SIPCORE_TARGET)

# Run extended parser tests
test_parser_ext: $(TEST_PARSER_EXT_TARGET)
	$(TEST_PARSER_EXT_TARGET)

# Run extended utils tests
test_utils_ext: $(TEST_UTILS_EXT_TARGET)
	$(TEST_UTILS_EXT_TARGET)

# Run extended sipcore tests
test_sipcore_ext: $(TEST_SIPCORE_EXT_TARGET)
	$(TEST_SIPCORE_EXT_TARGET)

# Run transaction/dialog tests
test_transaction: $(TEST_TRANSACTION_TARGET)
	$(TEST_TRANSACTION_TARGET)

# Run xmlconfig tests
test_xmlconfig: $(TEST_XMLCONFIG_TARGET)
	$(TEST_XMLCONFIG_TARGET)

# Run concurrent queue tests
test_concurrent_queue: $(TEST_CONCURRENT_QUEUE_TARGET)
	$(TEST_CONCURRENT_QUEUE_TARGET)

# Run logger tests
test_logger: $(TEST_LOGGER_TARGET)
	$(TEST_LOGGER_TARGET)

# Run ALL tests (basic + extended)
test_all: test test_utils test_sipcore test_parser_ext test_utils_ext test_sipcore_ext test_transaction test_xmlconfig test_concurrent_queue test_logger

asan_test_all:
	$(MAKE) clean $(ASAN_BUILD_DIR)/test_parser $(ASAN_BUILD_DIR)/test_utils $(ASAN_BUILD_DIR)/test_sipcore $(ASAN_BUILD_DIR)/test_parser_extended $(ASAN_BUILD_DIR)/test_utils_extended $(ASAN_BUILD_DIR)/test_sipcore_extended $(ASAN_BUILD_DIR)/test_transaction $(ASAN_BUILD_DIR)/test_xmlconfig $(ASAN_BUILD_DIR)/test_concurrent_queue $(ASAN_BUILD_DIR)/test_logger BUILD_DIR=$(ASAN_BUILD_DIR) CXXFLAGS="$(CXXFLAGS) $(ASAN_UBSAN_FLAGS)" LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined"
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_parser
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_utils
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_sipcore
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_parser_extended
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_utils_extended
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_sipcore_extended
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_transaction
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_xmlconfig
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_concurrent_queue
	$(ASAN_ENV) $(UBSAN_ENV) ./$(ASAN_BUILD_DIR)/test_logger

tsan_test_sipcore_ext:
	$(MAKE) clean $(TSAN_BUILD_DIR)/test_sipcore_extended BUILD_DIR=$(TSAN_BUILD_DIR) CXXFLAGS="$(CXXFLAGS) $(TSAN_FLAGS)" LDFLAGS="$(LDFLAGS) -fsanitize=thread"
	$(TSAN_ENV) ./$(TSAN_BUILD_DIR)/test_sipcore_extended

.PHONY: all clean rebuild debug release run run_plain run_tls test test_utils test_sipcore test_parser_ext test_utils_ext test_sipcore_ext test_transaction test_xmlconfig test_concurrent_queue test_logger test_all asan_test_all tsan_test_sipcore_ext
