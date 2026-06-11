# Convenience helper. Original experiment scripts are under src/cpp/.
# Example: make build TARGET=EdgeOrientDelta_TriangleLDP_RRAttack_strict
CXX ?= g++
CXXFLAGS ?= -O2 -std=c++11
TARGET ?= EdgeOrientDelta_TriangleLDP_RRAttack_strict
SRC := src/cpp/$(TARGET).cpp
BIN := build/$(TARGET)

.PHONY: build clean
build:
	mkdir -p build
	$(CXX) $(CXXFLAGS) -I src/cpp/include -o $(BIN) $(SRC)

clean:
	rm -rf build
