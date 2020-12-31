#ifndef CLOCK_H_
#define CLOCK_H_

/* Standard includes. */
#include <stdint.h>

/**
 * @brief The timer query function.
 *
 * This function returns the elapsed time.
 *
 * @return Time in milliseconds.
 */
uint32_t Clock_GetTimeMs( void );

/**
 * @brief Millisecond sleep function.
 *
 * @param[in] sleepTimeMs milliseconds to sleep.
 */
void Clock_SleepMs( uint32_t sleepTimeMs );

#endif /* ifndef CLOCK_H_ */

