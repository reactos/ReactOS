/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Public header
 * COPYRIGHT:   Copyright 2017-2018 Hermes Belusca-Maito
 */

#pragma once

/* Needed PSDK headers when using this library */
#if 0

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <winxxx.h>

#endif

/* NOTE: Please keep the header inclusion order! */

extern HANDLE ProcessHeap;

#include "errorcode.h"
#include "linklist.h"
#include "ntverrsrc.h"
// #include "arcname.h"
#include "bldrsup.h"
#include "filesup.h"
#include "fsutil.h"
#include "genlist.h"
#include "inicache.h"
#include "partlist.h"
#include "arcname.h"
#include "osdetect.h"

/* EOF */
