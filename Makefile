# 컴파일러 설정
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g -I./include -pthread
LDFLAGS = -pthread

# 디렉토리 설정
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/my_siplite

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
run: all
	./$(TARGET)

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

.PHONY: all clean rebuild debug release run test test_utils test_sipcore test_parser_ext test_utils_ext test_sipcore_ext test_transaction test_xmlconfig test_concurrent_queue test_logger test_all