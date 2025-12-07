# 컴파일러 설정
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g -I./include
LDFLAGS = 

# 디렉토리 설정
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/my_siplite

# 소스 파일 찾기
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))

# 기본 타겟
all: $(BUILD_DIR) $(TARGET)

# 빌드 디렉토리 생성
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 실행 파일 링크
$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

# 오브젝트 파일 컴파일
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
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
release: LDFLAGS += -s
release: all

# 실행
run: all
	./$(TARGET)

.PHONY: all clean rebuild debug release run