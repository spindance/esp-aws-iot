#include "clock.h"
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

uint32_t Clock_GetTimeMs( void ) {
    int64_t time_us = esp_timer_get_time();
    if (time_us < 0) {
        time_us = 0;
    }
    uint64_t time_ms = (uint64_t)time_us / 1000;
    return (uint32_t)(time_ms & 0xFFFFFFFF);
}

void Clock_SleepMs( uint32_t sleepTimeMs ) {
    // Round up to the nearest multiple of the tick period
    uint32_t remainder = sleepTimeMs % portTICK_PERIOD_MS;
    uint32_t rounded_sleepTimeMs = 0;
    if (remainder == 0) {
        rounded_sleepTimeMs = sleepTimeMs;
    } else {
        rounded_sleepTimeMs = sleepTimeMs + portTICK_PERIOD_MS - remainder;
    }

    uint32_t delay_ticks = rounded_sleepTimeMs / portTICK_PERIOD_MS;
    vTaskDelay(delay_ticks);
}
