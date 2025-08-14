# to build the libJsonObject`

#CPP=arm-buildroot-linux-gnueabihf-g++
CPP=g++

PROJECT:=libJsonObjects
PROJECT_MAP:=$(PROJECT).map
PROJECT_TARGET:=$(PROJECT).so

PROJECT_CFLAGS=$(CFLAGS) -fPIC -shared
PROJECT_IFLAGS=$(IFLAGS) -I.

PROJECT_LFLAGS=$(LDFLAGS) -rdynamic -funwind-tables -ffunction-sections -finstrument-functions -no-pie -lm -ldl -lrt  -shared

PROJECT_HEADER:=$(wildcard *.h) $(wildcard *.inl)
PROJECT_SOURCE:=$(wildcard *.cpp)
PROJECT_DEPEND:=$(patsubst %.cpp,%.o,$(PROJECT_SOURCE))

all: $(PROJECT_TARGET)

$(PROJECT_TARGET): $(PROJECT_DEPEND) # $(PROJECT_HEADER)
	@echo "Building target - $@"
	$(CPP) $(PROJECT_LFLAGS) -o $@ $^

%.o:%.cpp
	@echo "CPP [C] - $@"
	$(CPP) $(PROJECT_CFLAGS) $(PROJECT_IFLAGS) -c -o $@ $<

clean:
	@find ./ \( -name "*.o" -o -name "*.d" \) -exec rm -f '{}' \;
	@rm -f $(PROJECT_MAP) $(PROJECT_TARGET)

-include $(PROJECT_DEPEND:.o=.d)
