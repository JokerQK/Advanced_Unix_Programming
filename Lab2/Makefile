CPP = g++
CFLAGS = -g -Wall
SHFLAGS = -shared -fPIC
LDL = -ldl
LARGE = -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

PROGS = hw2.cpp logger.cpp sample.cpp

all: $(PROGS)
	$(CPP) -o logger $(CFLAGS) hw2.cpp print.cpp $(LDL)
	$(CPP) -o logger.so $(SHFLAGS) logger.cpp print.cpp $(LDL)
	$(CPP) $(LARGE) -o sample $(CFLAGS) sample.cpp
clean:
	rm -f -r logger.so logger sample *.dSYM *.txt core aaaa bbbb
run:
	./logger ./sample
	