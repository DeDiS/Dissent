include(dissent.pro)
TEMPLATE = app
TARGET = bench
DEPENDPATH += ext/googletest/src \
              ext/googletest/include/gtest \
              ext/googletest/include/gtest/internal
INCLUDEPATH += src \
               ext/googletest \
               ext/googletest/include \
               utils/bench
#DEFINES += QT_NO_DEBUG_OUTPUT
#DEFINES += QT_NO_WARNING_OUTPUT
#DEFINES += PBC_DEBUG

# Input
HEADERS += ext/googletest/include/gtest/gtest-death-test.h \
           ext/googletest/include/gtest/gtest-message.h \
           ext/googletest/include/gtest/gtest-param-test.h \
           ext/googletest/include/gtest/gtest-printers.h \
           ext/googletest/include/gtest/gtest-spi.h \
           ext/googletest/include/gtest/gtest-test-part.h \
           ext/googletest/include/gtest/gtest-typed-test.h \
           ext/googletest/include/gtest/gtest.h \
           ext/googletest/include/gtest/gtest_pred_impl.h \
           ext/googletest/include/gtest/gtest_prod.h \
           ext/googletest/include/gtest/internal/gtest-death-test-internal.h \
           ext/googletest/include/gtest/internal/gtest-filepath.h \
           ext/googletest/include/gtest/internal/gtest-internal.h \
           ext/googletest/include/gtest/internal/gtest-linked_ptr.h \
           ext/googletest/include/gtest/internal/gtest-param-util-generated.h \
           ext/googletest/include/gtest/internal/gtest-param-util.h \
           ext/googletest/include/gtest/internal/gtest-port.h \
           ext/googletest/include/gtest/internal/gtest-string.h \
           ext/googletest/include/gtest/internal/gtest-tuple.h \
           ext/googletest/include/gtest/internal/gtest-type-util.h \
           utils/bench/Benchmark.hpp

SOURCES += ext/googletest/src/gtest-all.cc \
           utils/bench/MainBench.cpp\
           utils/bench/MicroLength.cpp
