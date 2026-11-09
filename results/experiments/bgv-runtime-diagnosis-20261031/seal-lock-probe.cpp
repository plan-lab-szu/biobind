#include <seal/util/locks.h>
#ifdef SEAL_USE_SHARED_MUTEX
#error "This probe must use SEAL's stock atomic ReaderWriterLocker fallback."
#endif
#define NOMINMAX
#include <windows.h>
#include <cstdio>
static DWORD handles() { DWORD n=0; GetProcessHandleCount(GetCurrentProcess(),&n); return n; }
int main() {
    DWORD before=handles();
    #pragma omp parallel for num_threads(4)
    for (int i=0;i<20000;++i) {
        seal::util::ReaderWriterLocker m;
        { auto lock=m.acquire_write(); }
        { auto lock=m.acquire_read(); }
    }
    DWORD after=handles();
    std::printf("{\"iterations\":20000,\"handles_before\":%lu,\"handles_after\":%lu,\"delta\":%ld}\n",before,after,static_cast<long>(after-before));
}
