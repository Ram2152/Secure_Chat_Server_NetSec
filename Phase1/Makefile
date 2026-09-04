CXX=g++
CXXFLAGS=-Wall -Wno-format-truncation -O2 -std=c++17 -pthread
all: server client
server: server.cc common.cc common.hh
	$(CXX) $(CXXFLAGS) server.cc common.cc -o server
client: client.cc common.cc common.hh
	$(CXX) $(CXXFLAGS) client.cc common.cc -o client
clean:
	rm -f server client
