#include "my_stdio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asclin.h"

#define BUFSIZE 128
#define KB_BS '\x7F'
#define KB_CR '\r'

void MyStdio_Init (void)
{
    /* Initialize */
    Asclin0_InitUart();
}

static void remove_null (char *s)
{
    int i, start_idx;
    char buf[128];

    start_idx = 0;
    while (*(s + start_idx++) == '\0')
        ;
    memset(buf, 0, 128);
    strcpy(buf, (s + (start_idx - 1)));

    memset(s, 0, 128);
    i = 0;
    while (buf[i] != '\0')
    {
        *(s + i) = buf[i];
        ++i;
    }
    *(s + i) = '\0';
}

void my_puts (const char *str)
{
    char buffer[BUFSIZE];
    char *ptr;

    sprintf(buffer, "%s\r\n", str);

    for (ptr = buffer; *ptr; ++ptr)
        Asclin0_OutUart((const unsigned char) *ptr);
}

void my_printf (const char *fmt, ...)
{
    char buffer[128];
    char buffer2[128]; // add \r before \n
    int16_t len = 0;
    va_list ap;

    va_start(ap, fmt);
    vsprintf(buffer, fmt, ap);
    va_end(ap);
    int j = 0;
    for (int i = 0; buffer[i]; i++)
    {
        if (buffer[i] == '\n')
        {
            buffer2[j++] = '\r';
            buffer2[j++] = buffer[i];
        }
        else
        {
            buffer2[j++] = buffer[i];
        }
        len += 1;
    }
    buffer2[j] = '\0';
    len += 1;

    for (int i = 0; buffer2[i] != '\0'; i++)
        Asclin0_OutUart((const unsigned char) buffer2[i]);
}

void my_scanf (const char *fmt, ...)
{
    uint8_t c = 0;
    char buf[128];
    int idx = 0, i;
    char *pstr, *pidx;

    memset(buf, 0, 128);
    while (c != '\r')
    {
        c = Asclin0_InUart();
        if (c == KB_BS || c == 0x8)
        {
            if (idx > 0)
            {
                buf[idx - 1] = 0;
                idx--;
                my_printf("%c %c", 8, 8);
            }
            continue;
        }
        else
        {
            if (c == KB_CR)
            {
                idx += 1;
                buf[idx] = '\0';
            }
            else
            {
                buf[idx] = c;
                idx += 1;
            }
        }
        my_printf("%c", c);
    }
    my_printf("\n");

    va_list ap;
    va_start(ap, fmt);
    while ((c = *fmt++) != 0)
    {
        if (c == '%')
        {
            uint8_t c1;
            c = *fmt++;
            switch (c)
            {
                case 'c' :
                    *va_arg(ap, char*) = buf[0];
                    buf[0] = '\0';
                    break;
                case 'd' :
                    *va_arg(ap, int*) = atoi(buf);
                    pidx = strchr(buf, ' ');
                    if (pidx != NULL)
                    {
                        *pidx = '\0';
                    }
                    for (i = 0;; i++)
                    {
                        if (buf[i] == '\0' || buf[i] == ' ')
                        {
                            buf[i] = '\0';
                            break;
                        }
                        buf[i] = '\0';
                    }
                    break;
                case 's' :
                    pstr = va_arg(ap, char*);
                    for (i = 0; buf[i] != '\0'; i++)
                    {
                        *pstr++ = buf[i];
                        buf[i] = '\0';
                    }
                    *pstr = '\0';
                    break;
                case 'l' :
                    c1 = *fmt++;
                    if (c1 == 'd')
                    {
                        *va_arg(ap, long long*) = atoll(buf);
                        pidx = strchr(buf, ' ');
                        if (pidx != NULL)
                        {
                            *pidx = '\0';
                        }
                        for (i = 0;; i++)
                        {
                            if (buf[i] == '\0' || buf[i] == ' ')
                            {
                                buf[i] = '\0';
                                break;
                            }
                            buf[i] = '\0';
                        }
                    }
                    else if (c1 == 'f')
                    {
                        *va_arg(ap, double*) = atof(buf);
                        pidx = strchr(buf, ' ');
                        if (pidx != NULL)
                        {
                            *pidx = '\0';
                        }
                        for (int i = 0;; i++)
                        {
                            if (buf[i] == '\0' || buf[i] == ' ')
                            {
                                buf[i] = '\0';
                                break;
                            }
                            buf[i] = '\0';
                        }
                    }
                    break;
                case 'f' :
                    *va_arg(ap, float*) = (float) (atof(buf));
                    pidx = strchr(buf, ' ');
                    if (pidx != NULL)
                    {
                        *pidx = '\0';
                    }
                    for (i = 0;; i++)
                    {
                        if (buf[i] == '\0' || buf[i] == ' ')
                        {
                            buf[i] = '\0';
                            break;
                        }
                        buf[i] = '\0';
                    }
                    break;
                default :
                    break;
            }
            remove_null(buf);
        }
    }
    va_end(ap);
}
