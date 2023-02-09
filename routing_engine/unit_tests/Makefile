INC_DIRS := ../inc \
	    ../deps/libpcap
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

LDLIBS := -lpcap -lpthread

GTEST_DIR = ../deps/googletest/googletest

USER_DIR = .

CPPFLAGS += -isystem $(GTEST_DIR)/include \
		$(INC_FLAGS)

CXXFLAGS += -g -Wall -Wextra -pthread

TEST_SRC = $(shell find $(USER_DIR) -name 'test_*.cpp')
TESTS = $(basename $(TEST_SRC))

GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h

all : $(TESTS)

clean :
	rm -f $(TESTS) gtest.a gtest_main.a
	find . -name '*.o' -delete

GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

$(TESTS).o: %.o : %.cpp $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDLIBS) -c $< -o $@

$(TESTS) : % : %.o gtest_main.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDLIBS) $^ -o $@
