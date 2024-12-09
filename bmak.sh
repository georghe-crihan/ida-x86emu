#!/bin/sh
function c()
{
local C=${1}
g++ -g -D_DEBUG  -D__MAC__ -fvisibility=hidden -fvisibility-inlines-hidden \
-D__X64__ -I../../include/ -I. \
-I /Library/Developer/CommandLineTools/usr/include/c++/v1 \
-I /Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/ \
-DNO_OBSOLETE_FUNCS -Wall -Wextra -Wno-sign-compare -Wno-parentheses -Wshadow -Wunused -Wformat=2 -Werror=format-security -Werror=format-nonliteral -Wno-missing-field-initializers -fdiagnostics-show-option -fno-caret-diagnostics -Wno-invalid-source-encoding -Wno-unused-const-variable -Wno-unused-private-field -Wno-logical-op-parentheses -Wno-self-assign -Wno-logical-not-parentheses -Wno-parentheses-equality -Wno-dynamic-class-memaccess -Wno-unused-variable -Wno-unused-function -Wno-char-subscripts -Wno-null-conversion -Wno-int-to-pointer-cast -fwrapv -arch x86_64 -mmacosx-version-min=10.5 -isysroot /Library/Developer/CommandLineTools -m64 -fPIC -pipe -fno-strict-aliasing   -D__IDP__ -D__PLUGIN__ -fno-rtti -c \
-o obj/x64_mac_gcc_32/${C}.o ${C}.cpp
}

#qmake -o Makefile64.g++ x86emu64.pro -platform macx-g++
rm -f ../../bin/plugins/x86emu.dylib '/Users/mac/Applications/IDA Pro 7.0/ida.app/Contents/MacOS/plugins/x86emu.dylib'
#c emufuncs
make -f Makefile64.g++
make -f makefile.ida __MAC__=1 OBJDIR=p64
#cp ../../bin/plugins/x86emu.dylib '/Users/mac/Applications/IDA Pro 7.0/ida.app/Contents/MacOS/plugins/'
