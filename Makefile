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

.PHONY: all clean rebuild debug release run test