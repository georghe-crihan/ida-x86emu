* Make it work (now it crashes).
* Fix FIXMEs.
* Remove obsolete APIs.
* Signle Makefile / build script.
Currently you have to:
1. Build the QT's qmake / make generated plugin.
2. Run bmak.sh to build via IDA SDK.
Unfortunately now the QT version is not loadable.
Probably the reason is missing plugin exports.
