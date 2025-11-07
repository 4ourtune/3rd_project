#ifndef UTILS_MY_MATH_H_
#define UTILS_MY_MATH_H_

static inline int my_abs (int value)
{
    return (value < 0) ? -value : value;
}

static inline int my_clamp (int value, int min, int max)
{
    if (value > max)
        return max;
    if (value < min)
        return min;
    return value;
}

#endif /* UTILS_MY_MATH_H_ */
