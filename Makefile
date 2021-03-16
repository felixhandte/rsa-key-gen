
CC=clang-11
CXX=clang++-11
CPPFLAGS?=-DNDEBUG
CXXFLAGS?=-std=c++17 -O3 -Wall -Wextra -Werror
LDFLAGS?=-lssl -lcrypto

.PHONY: all
all : collider

collider.o : collider.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $^

collider : collider.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
