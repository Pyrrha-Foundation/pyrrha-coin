#!/bin/bash

LIBGMP_VERSION="6.3.0"

# check for -h or --help in the args
for var in "$@"
do
    if [ "$var" = "-h" ] || [ "$var" = "--help" ]; then
        echo "This script will configure the build tree to build libnexa for wasm then build it."
        echo "To reset the build tree run 'make distclean'"
        echo "./autogen.sh must be run before running this script."
        echo "All parameters passed into this script will be passed into configure"
        exit 0
    fi
done


# ensure we are in the nexa source root dir
if [ ! -f ./autogen.sh ]; then
    echo "Build script must be run from the nexa source root dir"
    exit 1
fi

if [ ! -f ./Makefile.am ]; then
    echo "Build script must be run from the nexa source root dir"
    exit 1
fi

if [ ! -f ./configure ]; then
    echo "Run ./autogen.sh before running this script"
    exit 1
fi

rm -rf gmp-$LIBGMP_VERSION
rm -rf boost_1_86_0
rm -rf build-libnexa-wasm

cwd=$(pwd)

cd $HOME

if [ ! -d emsdk ]; then

    # Get the emsdk repo
    git clone https://github.com/emscripten-core/emsdk.git
fi
# Enter that directory
cd emsdk
# Fetch the latest version of the emsdk (not needed the first time you clone)
git pull
# Download and install the latest SDK tools.
./emsdk install latest
# Make the "latest" SDK "active" for the current user. (writes .emscripten file)
./emsdk activate latest
# Activate PATH and other environment variables in the current terminal
source ./emsdk_env.sh

cd $cwd

if [ ! -d gmp-6.3.0 ]; then
    # need to compile libgmp for wasm to run build libnexa for wasm
    wget https://gmplib.org/download/gmp/gmp-$LIBGMP_VERSION.tar.xz
    tar -xf gmp-$LIBGMP_VERSION.tar.xz
    cd gmp-$LIBGMP_VERSION
    emconfigure ./configure ABI=standard --enable-cxx --host=none --disable-assembly --prefix=$HOME/emsdk/upstream/emscripten/cache/sysroot
    emmake make -j `nproc`
    emmake make install
    cd ..
    rm -rf gmp-$LIBGMP_VERSION.tar.xz
fi


if [ ! -d boost_1_86_0 ]; then
    # copy the boost headers into the emscript sysroot, no need to compile the libs.
    wget https://archives.boost.io/release/1.86.0/source/boost_1_86_0.tar.gz
    tar -xf boost_1_86_0.tar.gz
    cd boost_1_86_0
    cp -R ./boost $HOME/emsdk/upstream/emscripten/cache/sysroot/include
    cd ..
    rm -rf boost_1_86_0.tar.gz
fi

./autogen.sh
mkdir build-libnexa-wasm
cd build-libnexa-wasm
mkdir .libs
cp $cwd/gmp-$LIBGMP_VERSION/.libs/libgmp.a ./.libs/
if ! emconfigure ../configure --enable-only-libnexa --enable-libnexa-wasm --prefix=$HOME/emsdk/upstream/emscripten/cache/sysroot; then
    exit 2
fi

if ! emmake make -j`nproc`; then
    exit 3
fi

cd src
emcc -o libnexa.js ./.libs/libnexa.a ./secp256k1/.libs/libsecp256k1.a ../.libs/libgmp.a \
-sEXPORTED_FUNCTIONS='["_malloc", "_free",
"_libnexaVersion", "_get_libnexa_error", "_get_libnexa_error_string", "_encode64", "_decode64", "_Bin2Hex",
"_hd44DeriveChildKey", "_GetPubKey", "_SignHashEDCSA", "_txid", "_txidem", "_blockHash",
"_SignTxECDSA", "_signBchTxOneInputUsingSchnorr", "_signTxOneInputUsingSchnorr", "_SignTxSchnorr",
"_signHashSchnorr", "_signHashSchnorrWithNonce", "_parseGroupDescription", "_getArgsHashFromScriptPubkey",
"_getTemplateHashFromScriptPubkey", "_getGroupTokenInfoFromScriptPubkey", "_signMessage",
"_verifyMessage", "_verifyBlockHeader", "_encodeCashAddr", "_decodeCashAddr", "_decodeCashAddrContent",
"_serializeScript", "_pubkeyToScriptTemplate", "_groupIdFromAddr", "_groupIdToAddr",
"_decodeWifPrivateKey", "_sha256", "_hash256", "_hash160", "_getWorkFromDifficultyBits",
"_getDifficultyBitsFromWork", "_createBloomFilter", "_extractFromMerkleBlock", "_capdSolve",
"_capdCheck", "_capdHash", "_cryptAES256CBC", "_verifyDataSchnorr", "_verifyHashSchnorr", "_RandomBytes",
"_CreateNoContextScriptMachine", "_CreateScriptMachine", "_CreateScriptMachine", "_SmRelease", "_SmClone",
"_SmEval", "_SmBeginStep", "_SmStep", "_SmPos", "_SmEndStep", "_SmReset", "_SmSetStackItem",
"_SmGetStackItem", "_SmGetError"]' \
-sEXPORTED_RUNTIME_METHODS='["UTF8ToString", "stringToUTF8", "setValue", "getValue"]'


exit 0
