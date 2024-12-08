
#your Ida SDK location either relative to ida-x86emu/trunk
#or absolute
SDK = ../..

OBJECTS_DIR = p64

#Need to change the following to your Ida install location
win32:IDA_APP = "C:/Program Files/Ida"
linux-g++:IDA_APP = /opt/ida-$$(IDA_VERSION)
macx:IDA_APP = "/Applications/IDA Pro $$(IDA_VERSION)/idaq.app/Contents"
macx:IDA_LIB = "$${SDK}/lib/x64_mac_gcc_64/"

#Need to change the following to your Qt install location
macx:QT_LOC = /Users/Shared/Qt/5.6.0-x64/lib
macx:QT_TAIL = QtWidgets.framework/Versions/5/Headers
#./lib/QtWidgets.framework/Versions/5/Headers/
#create our own list of Qt modules
macx:QMAKE_INCDIR = $${QT_LOC}/$${QT_TAIL}

TEMPLATE = lib

QT += widgets

CONFIG += qt dll

INCLUDEPATH += $${SDK}/include

DESTDIR = $${SDK}/bin/plugins

DEFINES += __IDP__ __QT__ __EA64__ __X64__ __PLUGIN__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32:DEFINES += _CRT_SECURE_NO_WARNINGS
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32:LIBS += comdlg32.lib gdi32.lib user32.lib advapi32.lib ida.lib
win32-msvc2008: {
   exists( $${SDK}/lib/vc.w64/ida.lib ) {
      LIBS += -L$${SDK}/lib/vc.w64
   } else {
      LIBS += -L$${SDK}/lib/x86_win_vc_64
   }
}
linux-g++:LIBS += -L$${IDA_APP} -lida64
macx:LIBS += -L$${IDA_LIB} -lida64

#don't let qmake force search any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT =

#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -F$${QT_LOC}

linux-g++:QMAKE_CXXFLAGS =

#macx:QMAKE_LFLAGS += -F$${IDA_APP}/Frameworks
macx:QMAKE_LIBDIR_QT =

SOURCES = x86emu.cpp \
   x86emu_ui_qt.cpp \
	emufuncs.cpp \
	cpu.cpp \
	emuheap.cpp \
	memmgr.cpp \
	seh.cpp \
	break.cpp \
	hooklist.cpp \
	buffer.cpp \
	emuthreads.cpp \
	peutils.cpp \
	emu_script.cpp \
	context.cpp

HEADERS = break.h \
   bsd_syscalls.h \
   buffer.h \
   context.h \
   cpu.h \
   elf32.h \
   elf_common.h \
   emu_script.h \
   emufuncs.h \
   emuheap.h \
   emuthreads.h \
   hooklist.h \
   linux_syscalls.h \
   memmgr.h \
   peutils.h \
   sdk_versions.h \
   seh.h \
   x86emu_ui_qt.h \
   x86defs.h

win32:TARGET_EXT=.p64
linux-g++:TARGET_EXT=.plx64
macx:TARGET_EXT=.pmc64

TARGET = x86emu_qt
