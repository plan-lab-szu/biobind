#include <shared_mutex>
#include <windows.h>
#include <cstdio>
static DWORD handles() { DWORD n=0; GetProcessHandleCount(GetCurrentProcess(),&n); return n; }
int main() {
    DWORD before=handles();
    #pragma omp parallel for num_threads(4)
    for (int i=0;i<20000;++i) {
        std::shared_mutex m;
        m.lock(); m.unlock();
        m.lock_shared(); m.unlock_shared();
    }
    DWORD after=handles();
    std::printf("{\"iterations\":20000,\"handles_before\":%lu,\"handles_after\":%lu,\"delta\":%ld}\n",before,after,static_cast<long>(after-before));
}
