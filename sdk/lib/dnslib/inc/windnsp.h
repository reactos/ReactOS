/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS DNSAPI Header
 * PURPOSE:     DNSLIB Precompiled Header
 */

PVOID
WINAPI
DnsApiAlloc(
    IN DWORD Size
);

PVOID
WINAPI
DnsQueryConfigAllocEx(
    IN DNS_CONFIG_TYPE Config,
    OUT PVOID pBuffer,
    IN OUT PDWORD pBufferLength
);

PVOID
WINAPI
DnsApiFree(
    IN PVOID pBuffer
);

/* EOF */
