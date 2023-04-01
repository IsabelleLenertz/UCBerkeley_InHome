INC_DIRS := ../inc \
	    ../deps/libpcap
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

SRC_DIRS := ../src

BUILD_DIR := ../build

LDLIBS := -lpcap -lpthread -lcrypto

GTEST_DIR = ../deps/googletest/googletest

USER_DIR = .

CPPFLAGS += -isystem $(GTEST_DIR)/include \
		$(INC_FLAGS)

CXXFLAGS += -g -Wall -Wextra -pthread

TEST_SRC = $(shell find $(USER_DIR) -name 'test_*.cpp')

TESTS = $(basename $(TEST_SRC))
TEST_OBJS := $(TEST_SRC:%.cpp=%.cpp.o)

GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h

# Source Code
SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c')

OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
OBJS := $(filter-out $(BUILD_DIR)/../src/main.cpp.o,$(OBJS))

DEPS := $(OBJS:.o=.d)

all : $(TESTS)

clean :
	rm -f $(TESTS) gtest.a gtest_main.a
	find . -name '*.o' -delete
	rm -f test.txt

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

$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.cpp.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(TEST_OBJS): %.cpp.o : %.cpp $(GTEST_HEADERS)
	@echo Building test object file
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) \
	$(LDLIBS) -c $< -o $@

$(TESTS) : % : %.cpp.o gtest_main.a $(OBJS)
	@echo Building test executable
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) \
	$^ -o $@ $(LDLIBS)

-include $(DEPS)
