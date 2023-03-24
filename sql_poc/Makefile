TARGET_EXEC := hello_sql

BUILD_DIR := ./build
SRC_DIRS := ./src
LDLIBS := -lmysqlcppconn8 -lmysqlcppconn -lpthread

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c')

OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

DEPS := $(OBJS:.o=.d)

INC_DIRS := ./inc \
			/usr/include/mysql-cppconn-8/jdbc/ \
			/usr/include/mysql-cppconn-8/
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS := $(INC_FLAGS) -MMD -MP 
# -D_GLIBCXX_USE_CXX11_ABI=0

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDLIBS) $(LDFLAGS)

$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.cpp.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

all: $(BUILD_DIR)/$(TARGET_EXEC)

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)

-include $(DEPS)
