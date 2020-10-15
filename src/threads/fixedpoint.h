#define P 17
#define Q 14
#define F (1 << Q)

#define FIXPOINT(n) (n * F)
#define ROUNDZERO_INT(x) (x / F)
#define ROUNDNEAR_INT(x) ((x >= 0) ? (((x + (F / 2)) / F)) : (((x - (F / 2))) / F))
#define ADD_FIXED(x, y) (x + y)
#define ADD_INT(x, n) (x + n * F)
#define SUB_FIXED(x, y) (x - y)
#define SUB_INT(x, n) (x - n * F)
#define MUL_FIXED(x, y) ((int64_t x)*F / y)
#define MUL_INT(x, n) (x * n)
#define DIV_FIXED(x, y) ((int64_t x)*F / y)
#define DIV_INT(x, n) (x / n)