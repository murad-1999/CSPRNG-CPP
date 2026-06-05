CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread -O3 -Iinclude

SRCS = src/chacha20_csprng.cpp
TEST_SRCS = tests/chacha20_csprng_test.cpp

TARGET = chacha20_csprng_test

all: $(TARGET)

$(TARGET): $(SRCS) $(TEST_SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(TEST_SRCS) -o $(TARGET)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all test clean
