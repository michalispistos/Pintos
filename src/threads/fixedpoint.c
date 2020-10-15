#include <stdio.h>
#include "fixedpoint.h"

int main(void){
    printf("%d \n", ROUNDNEAR_INT(ADD_INT(FIXPOINT(-3),4)));
    return 0;
}