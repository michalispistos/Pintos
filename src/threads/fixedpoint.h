#define P 17
#define Q 14
#define F (1 << Q)

/* Macros used for fixed point arithmetic
   required for the advanced scheduler. */

/* Converts an integer into fixed point value */
#define FIXPOINT(n) (n * F)

/* Rounds a fixed point value to an integer towards zero */
#define ROUNDZERO_INT(x) (x / F)

/* Rounds a fixed point value to an integer towards nearest integer */
#define ROUNDNEAR_INT(x) ((x >= 0) ? (((x + (F / 2)) / F)) : (((x - (F / 2))) / F))

/* Adds a fixed point value (x) with another fixed point value (y) */
#define ADD_FIXED(x, y) (x + y)

/* Adds a fixed point value (x) with an integer (n) */
#define ADD_INT(x, n) (x + n * F)

/* Subtracts a fixed point value (y) from another fixed point value (x) */
#define SUB_FIXED(x, y) (x - y)

/* Subtracts an integer (n) from a fixed point value (x) */
#define SUB_INT(x, n) (x - n * F)

/* Multiplies a fixed point value (x) with another fixed point value (y) */
#define MUL_FIXED(x, y) ( ((int64_t) x)*y / F)

/* Multiplies a fixed point value (x) with an integer (n) */
#define MUL_INT(x, n) (x * n)

/* Divides a fixed point value (x) by another fixed point value (y) */
#define DIV_FIXED(x, y) ( ((int64_t) x) *F / y)

/* Divides a fixed point value (x) by an integer (n) */
#define DIV_INT(x, n) (x / n)
