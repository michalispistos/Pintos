#define P 17
#define Q 14
#define f (1 << Q)

#define FIXPOINT (n)(n * f)
#define ROUNDZERO_INT (x)(x / f)
#define ROUNDNEAR_INT (x)(x >= 0) ? ((x + f) / 2) : ((x - f) / 2)
#define ADD_FIXED (x, y)(x + y)
#define ADD_INT (x, n)(x + n * f)
