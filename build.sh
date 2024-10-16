#!/bin/bash

set -e
set -x

if [ $(uname -s) != "Darwin" ]; then

    SSL_CFLAGS=$(pkg-config --cflags openssl)
    SSL_LDFLAGS=$(pkg-config --libs openssl)
    if [ -z "$SSL_LDFLAGS" ]; then
        echo "OpenSSL development files not found. Please install libssl-dev."
        exit 1
    fi

    echo "*** Cloning ld64 repository ..."
    [ -d ld64 ] && rm -rf ld64
    git clone https://github.com/ProcursusTeam/ld64.git

    echo "*** Checking the non-darwin headers ..."
    if [ ! -d ./ld64/EXTERNAL_HEADERS/non-darwin ]; then
        echo "The non-darwin headers are not present in the ld64 repository."
    fi

    EXTRA_HEADER_FLAG="-I./ld64/EXTERNAL_HEADERS/non-darwin $SSL_CFLAGS $SSL_LDFLAGS"
fi

echo "*** Building the hashmacho executable ..."
clang -v $EXTRA_HEADER_FLAG -o hashmacho main.c

echo "*** Checking built hashmacho executable ..."
chmod +x ./hashmacho && ./hashmacho
