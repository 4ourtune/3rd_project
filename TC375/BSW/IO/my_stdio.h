#ifndef BSW_IO_MY_STDIO_H_
#define BSW_IO_MY_STDIO_H_

#include <stdint.h>

void MyStdio_Init (void);
void my_puts (const char *str);
void my_printf (const char *fmt, ...);
void my_scanf (const char *fmt, ...);

#endif /* BSW_IO_MY_STDIO_H_ */
