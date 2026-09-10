// mayhem/lsan_off.cc — build-time LeakSanitizer off-switch (SPEC §6.2 item 15).
//
// `-Zsanitizer=address` (rustc) bundles LeakSanitizer with no flag to drop just leak
// detection. Leaks are not the bug class this fleet fuzzes for, so every ASan-built
// fuzz binary links this strong definition; the sanitizer runtime calls it at exit and
// skips the leak check. ASan and UBSan stay fully active. Compiled by mayhem/build.sh
// (clang++ -gdwarf-3) and linked into each cargo-fuzz target via -Clink-arg.
extern "C" int __lsan_is_turned_off(void) { return 1; }
