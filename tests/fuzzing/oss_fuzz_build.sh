#!/bin/bash -eu

export LDFLAGS="${CFLAGS}"
./configure --enable-ctrls
make -j$(nproc)

# We need a few declarations from main.c
# so we rename main() to main2()
sed 's/int main(/int main2(/g' -i $SRC/proftpd/src/main.c

# Compile main.c again
export NEW_CC_FLAG="${CC} ${CFLAGS} -DHAVE_CONFIG_H -DLINUX  -I. -I./include"
$NEW_CC_FLAG -c src/main.c -o src/main.o
rm src/ftpdctl.o

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build fuzzer(s)
$NEW_CC_FLAG -c $SRC/fuzzer.c -o fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o $OUT/fuzzer \
	src/scoreboard.o \
	lib/prbase.a \
	fuzz_lib.a \
	-L/src/proftpd/lib \
	-lcrypt -pthread

# Controls API request parser fuzzer
cp tests/fuzzing/ctrls_request_fuzzer.c $SRC/ctrls_fuzzer.c
$NEW_CC_FLAG -c $SRC/ctrls_fuzzer.c -o ctrls_fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE ctrls_fuzzer.o -o $OUT/ctrls_fuzzer \
	src/scoreboard.o \
	lib/prbase.a \
	fuzz_lib.a \
	-L/src/proftpd/lib \
	-lcrypt -pthread

# Seed corpus for the Controls request fuzzer
if [ -d tests/fuzzing/corpus/ctrls_request ]; then
  zip -j $OUT/ctrls_fuzzer_seed_corpus.zip tests/fuzzing/corpus/ctrls_request/*
  cp -v tests/fuzzing/ctrls_fuzzer.dict $OUT/ctrls_fuzzer.dict
fi

# Build seed corpus
cd $SRC
git clone https://github.com/dvyukov/go-fuzz-corpus
zip $OUT/fuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/*

