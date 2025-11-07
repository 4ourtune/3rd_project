#include "byte_queue.h"

bool ByteQueue_Init (ByteQueue *q, int capacity)
{
    if (!q || capacity <= 0 || capacity > BYTE_QUEUE_MAX_BUF_SIZE)
        return false;

    q->head = 0;
    q->tail = 0;
    q->capacity = capacity;

    return true;
}

bool ByteQueue_Push (ByteQueue *q, uint8_t byte)
{
    if (q->capacity <= 0)
        return false;

    q->buffer[q->tail] = byte;
    q->tail = (q->tail + 1) % q->capacity;

    if (q->tail == q->head) // 큐가 가득 찬 경우
    {
        q->head = (q->head + 1) % q->capacity; // 가장 오래된 항목 삭제
    }

    return true;
}

bool ByteQueue_Pop (ByteQueue *q, uint8_t *byte)
{
    if (q->capacity <= 0 || q->head == q->tail) // 큐가 비어있는지 확인
        return false;

    *byte = q->buffer[q->head];
    q->head = (q->head + 1) % q->capacity;

    return true;
}
