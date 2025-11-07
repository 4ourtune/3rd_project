#ifndef UTILS_QUEUE_BYTE_QUEUE_H_
#define UTILS_QUEUE_BYTE_QUEUE_H_

#include <stdbool.h>
#include <stdint.h>

#define BYTE_QUEUE_MAX_BUF_SIZE 64

typedef struct
{
    uint8_t buffer[BYTE_QUEUE_MAX_BUF_SIZE];    // 고정 크기 버퍼
    int head;                                   // 읽기 위치
    int tail;                                   // 쓰기 위치
    int capacity;                               // 현재 사용하는 버퍼 크기 (<= BYTE_QUEUE_MAX_BUF_SIZE)
} ByteQueue;

bool ByteQueue_Init (ByteQueue *q, int capacity);
bool ByteQueue_Push (ByteQueue *q, uint8_t byte);
bool ByteQueue_Pop (ByteQueue *q, uint8_t *byte);

#endif /* UTILS_QUEUE_BYTE_QUEUE_H_ */
