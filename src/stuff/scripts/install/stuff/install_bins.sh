#!/bin/sh

$PREFIX/stuff/install_bin.sh /src/webtester  webtester.bin    \
  webtester webtester 0775   false

$PREFIX/stuff/install_bin.sh /src/stuff/scripts cjar.sh    \
  webtester webtester 0775   false

($DIST_INST && $PREFIX/stuff/install_bin.sh /src/frontend gwebtester \
  webtester webtester 0775   false)

