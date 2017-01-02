#!/bin/sh

${DIST_INST} && $PREFIX/stuff/install_lib.sh /src/libwebtester    \
  libwebtester.so   webtester webtester 0775

$PREFIX/stuff/install_lib.sh /src/stuff/testlib \
  libtestlib.so     webtester webtester 0775

$PREFIX/stuff/install_lib.sh /src/stuff/testlib++ \
  libtestlib++.so   webtester webtester 0775
