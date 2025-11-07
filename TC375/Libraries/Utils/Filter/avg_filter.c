#include "avg_filter.h"

bool Filter_Init (AverageFilter *filter, int size)
{
    if (!filter || size <= 0 || size > AVG_FILTER_MAX_BUF_SIZE)
        return false;

    for (int i = 0; i < size; i++)
        filter->buffer[i] = 0;

    filter->filter_size = size;
    filter->next_index = 0;
    filter->data_cnt = 0;
    filter->sum = 0;

    return true;
}

int32_t Filter_Update (AverageFilter *filter, int32_t new_value)
{
    if (!filter || filter->filter_size <= 0 || filter->filter_size > AVG_FILTER_MAX_BUF_SIZE)
        return 0;

    int idx = filter->next_index;
    int32_t old_value = filter->buffer[idx];

    if (filter->data_cnt < filter->filter_size)
        filter->data_cnt++;
    else
        filter->sum -= old_value;

    filter->buffer[idx] = new_value;
    filter->sum += new_value;
    filter->next_index = (idx + 1) % filter->filter_size;

    return (int32_t) (filter->sum / filter->data_cnt);
}

bool Filter_Reset (AverageFilter *filter)
{
    if (!filter)
        return false;

    for (int i = 0; i < filter->filter_size; i++)
        filter->buffer[i] = 0;

    filter->next_index = 0;
    filter->data_cnt = 0;
    filter->sum = 0;

    return true;
}
