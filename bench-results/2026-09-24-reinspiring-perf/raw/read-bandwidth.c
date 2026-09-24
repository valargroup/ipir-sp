// Diagnostic lower bound: read the same 1.75 GiB resident allocation, no crypto.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
int main(void) {
    const size_t bytes=(size_t)28672*32768*2, n=bytes/8;
    uint64_t *p=aligned_alloc(64,bytes);
    if(!p)return 1;
    for(size_t i=0;i<n;i++)p[i]=i*UINT64_C(6364136223846793005)+1;
    for(int nt=1;nt<=8;nt*=8) {
        omp_set_num_threads(nt);
        for(int r=0;r<33;r++) {
            uint64_t sum=0;
            double start=omp_get_wtime();
            #pragma omp parallel for reduction(^:sum) schedule(static)
            for(size_t i=0;i<n;i++)sum^=p[i];
            double ms=(omp_get_wtime()-start)*1000;
            if(r>=3)printf("{\"kind\":\"sample\",\"name\":\"memory_read\",\"threads\":%d,\"sample\":%d,\"ms\":%.6f,\"checksum\":\"%016lx\"}\n",nt,r-3,ms,(unsigned long)sum);
        }
    }
    free(p);
}
