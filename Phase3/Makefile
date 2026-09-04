CXX=g++
CXXFLAGS=-Wall -Wno-format-truncation -O2 -std=c++17 -pthread $(shell pkg-config --cflags openssl 2>/dev/null)
LIBS=$(shell pkg-config --libs-only-L openssl 2>/dev/null) -lcrypto
all: server client mitm
server: server.cc common.cc crypto.cc
	$(CXX) $(CXXFLAGS) server.cc common.cc crypto.cc -o server $(LIBS)
client: client.cc common.cc crypto.cc
	$(CXX) $(CXXFLAGS) client.cc common.cc crypto.cc -o client $(LIBS)
mitm: mitm.cc common.cc crypto.cc
	$(CXX) $(CXXFLAGS) mitm.cc common.cc crypto.cc -o mitm $(LIBS)
clean:
	rm -f server client mitm
