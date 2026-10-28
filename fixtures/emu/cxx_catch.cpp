// E9 fixture: a function that throws and catches a C++ exception internally (gcc x64 = SEH-based unwinding).
extern "C" __declspec(dllexport) __attribute__((noinline)) int cxx_catcher(int x) {
  try {
    if (x) throw 42;
    return 0;
  } catch (int v) {
    return v + 1;
  }
}
