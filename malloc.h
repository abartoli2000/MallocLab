#pragma once

#ifndef ALIGNMENT
# define ALIGNMENT 8
#endif

#define ALIGN(P) ((typeof (P)) (( (uintptr_t) P + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1)))

int dbg_printf (const char* fmt, ...);

#define printf(A...) dbg_printf (A)

////////////////////////////////////////////////////// This is taken from glibc
#define SIZE_SZ 8
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double)	\
                          ? __alignof__ (long double) : 2 * SIZE_SZ)


#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)					\
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz)						\
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))	\
   + SMALLBIN_CORRECTION)

#define largebin_index(sz)                                              \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) : \
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) : \
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) : \
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) : \
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) : \
   126)

#define SIZE_TO_BIN(sz)							\
  ((in_smallbin_range (sz)) ? smallbin_index (sz) : largebin_index (sz))
////////////////////////////////////////////////////////////////////////////////
