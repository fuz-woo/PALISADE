#Multi OS makefile
ifeq ($(OS),Windows_NT)

  #  ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
  #      CCFLAGS += -D AMD64
  #  endif
  #  ifeq ($(PROCESSOR_ARCHITECTURE),x86)
  #      CCFLAGS += -D IA32
  #  endif
    include Makefile.mingw64

else

    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        #CCFLAGS += -D LINUX
	include Makefile.lin
    endif
    ifeq ($(UNAME_S),Darwin)
        #CCFLAGS += -D OSX
	include Makefile.mac
    endif

    ifeq ($(UNAME_S),CYGWIN_NT-6.1)
        #CCFLAGS += -D CYGWIN
	include Makefile.mingw
    endif

  #  UNAME_P := $(shell uname -p)
  #  ifeq ($(UNAME_P),x86_64)
  #      CCFLAGS += -D AMD64
  #  endif
  #  ifneq ($(filter %86,$(UNAME_P)),)
  #      CCFLAGS += -D IA32
  #  endif
  #  ifneq ($(filter arm%,$(UNAME_P)),)
  #      CCFLAGS += -D ARM
  #  endif
endif

include Makefile.common
