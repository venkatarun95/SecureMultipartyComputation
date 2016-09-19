MEMORY_STYLE := ./protobufs-default

CXX := g++
CXXFLAGS := -DHAVE_CONFIG_H -std=c++11 -pthread -pedantic -Wall -Wextra -Weffc++ -Werror -Wno-vla -fno-default-inline -pg -O2
INCLUDES := -I.

LIBS     := -lm -lcrypto
OBJECTS  := channel.o coin-toss.o

all: psi

.PHONY: all

psi: $(OBJECTS) psi.o
	$(CXX) $(inputs) -o $(output) $(LIBS)

%.o: %.cc
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c $(input) -o $(output)
