TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpthread

#DEFINES += DEBUG

#QMAKE_CFLAGS += -fPIC -g -rdynamic
QMAKE_CXXFLAGS += -fPIC -g -rdynamic

SOURCES += main.c \
    ping.c \
    scanner.c \
    portlist.c

HEADERS += \
    ping.h \
    scanner.h \
    portlist.h
