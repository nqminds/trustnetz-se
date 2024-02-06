/* --------------------------------------------------------------------------
 * VaultIC API
 * Copyright (C) Inside Secure, 2011. All Rights Reserved.
 * -------------------------------------------------------------------------- */

#include "vaultic_common.h"

#if (VLT_PLATFORM == VLT_EMBEDDED)

#include "vaultic_timer_delay.h"

#include <errno.h>
#include <time.h>

static long long timeStop;

void VltSleep( VLT_U32 uSecDelay )
{
	struct timespec rqtp = {
		.tv_sec = uSecDelay / 1000000,
		.tv_nsec = (uSecDelay % 1000000) * 1000};
	struct timespec rmtp;

	/* Use nanosleep because usleep is deprecated */
	if (nanosleep(&rqtp, &rmtp) < 0) {
		if (errno == EINTR) {
			nanosleep(&rmtp, NULL);		// Retry once to sleep the remainder
		}	
	}
}
    
/**
* Starts a basic timer in milliseconds
*/
void VltTimerStart(VLT_U32 msDelay)
{
    struct timespec t ;
    long long timeStart;

    clock_gettime ( CLOCK_REALTIME , & t ) ;
    timeStart= t.tv_sec * 1000 + ( t.tv_nsec + 500000 ) / 1000000 ;
    timeStop =timeStart+ msDelay;
}

/**
* Stops the timer
*/
void VltTimerStop(void)
{
}

/**
* Returns TRUE if the timer is expired
*/
VLT_BOOL VltTimerIsExpired(void)
{
    struct timespec t ;
    long long timeNow;

    clock_gettime ( CLOCK_REALTIME , & t ) ;
    timeNow= t.tv_sec * 1000 + ( t.tv_nsec + 500000 ) / 1000000 ;

    return timeNow >= timeStop;
}

#endif /* VLT_EMBEDDED */
