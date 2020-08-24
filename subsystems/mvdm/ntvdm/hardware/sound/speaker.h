/*
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * PROJECT:         ReactOS Virtual DOS Machine
 * PURPOSE:         PC Speaker emulation
 * PROGRAMMERS:     Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#ifndef _SPEAKER_H_
#define _SPEAKER_H_

/* FUNCTIONS ******************************************************************/

VOID SpeakerChange(UCHAR Port61hValue);

VOID SpeakerInitialize(VOID);
VOID SpeakerCleanup(VOID);

#endif /* _SPEAKER_H_ */
