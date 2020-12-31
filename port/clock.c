#include "clock.h"

#include <pal_time.h>
#include <pal_task.h>

uint32_t Clock_GetTimeMs( void ) {
    return (uint32_t)(pal_time_ms_since_boot() & 0xFFFFFFFF);
}

void Clock_SleepMs( uint32_t sleepTimeMs ) {
    pal_task_delay_ms(sleepTimeMs);
}
