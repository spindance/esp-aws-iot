#pragma once

#include "logging_levels.h"

    /* Configure name and log level for the Shadow library. */
#ifndef LIBRARY_LOG_NAME
        #define LIBRARY_LOG_NAME     "SHADOW"
#endif
#ifndef LIBRARY_LOG_LEVEL
        #define LIBRARY_LOG_LEVEL    LOG_NONE
#endif

#include "logging_stack.h"
