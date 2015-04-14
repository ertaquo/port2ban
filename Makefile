C=g++
CFLAGS=-c -Wall
LDFLAGS=-lstdc++
SOURCES=main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
	EXECUTABLE=port2ban

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
