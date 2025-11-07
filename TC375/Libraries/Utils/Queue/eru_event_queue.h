#ifndef UTILS_QUEUE_ERU_EVENT_QUEUE_H_
#define UTILS_QUEUE_ERU_EVENT_QUEUE_H_

#include <stdbool.h>
#include <stdint.h>

#define ERU_EVENT_QUEUE_MAX_BUF_SIZE 64

typedef struct
{
    bool pin_state;
    uint64_t timestamp_us;
} EruEvent;

typedef struct
{
    EruEvent buffer[ERU_EVENT_QUEUE_MAX_BUF_SIZE];
    int head;
    int tail;
    int capacity;
} EruEventQueue;

bool EruEventQueue_Init (EruEventQueue *q, int capacity);
bool EruEventQueue_Push (EruEventQueue *q, const EruEvent *event);
bool EruEventQueue_Pop (EruEventQueue *q, EruEvent *out);

#endif /* UTILS_QUEUE_ERU_EVENT_QUEUE_H_ */
