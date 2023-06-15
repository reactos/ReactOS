/*
 * PROJECT:     ReactOS Task Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Performance Page.
 * COPYRIGHT:   Copyright 1999-2001 Brian Palmer <brianp@reactos.org>
 */

#include "precomp.h"
#include <shlwapi.h>

extern BOOL bInMenuLoop;        /* Tells us if we are in the menu loop - from taskmgr.c */

TM_GRAPH_CONTROL PerformancePageCpuUsageHistoryGraph;
TM_GRAPH_CONTROL PerformancePageMemUsageHistoryGraph;

HWND hPerformancePage;                /* Performance Property Page */
static HWND hCpuUsageGraph;                  /* CPU Usage Graph */
static HWND hMemUsageGraph;                  /* MEM Usage Graph */
HWND hPerformancePageCpuUsageHistoryGraph;           /* CPU Usage History Graph */
HWND hPerformancePageMemUsageHistoryGraph;           /* Memory Usage History Graph */
static HWND hTotalsFrame;                    /* Totals Frame */
static HWND hCommitChargeFrame;              /* Commit Charge Frame */
static HWND hKernelMemoryFrame;              /* Kernel Memory Frame */
static HWND hPhysicalMemoryFrame;            /* Physical Memory Frame */
static HWND hCpuUsageFrame;
static HWND hMemUsageFrame;
static HWND hCpuUsageHistoryFrame;
static HWND hMemUsageHistoryFrame;
static HWND hCommitChargeTotalEdit;          /* Commit Charge Total Edit Control */
static HWND hCommitChargeLimitEdit;          /* Commit Charge Limit Edit Control */
static HWND hCommitChargePeakEdit;           /* Commit Charge Peak Edit Control */
static HWND hKernelMemoryTotalEdit;          /* Kernel Memory Total Edit Control */
static HWND hKernelMemoryPagedEdit;          /* Kernel Memory Paged Edit Control */
static HWND hKernelMemoryNonPagedEdit;       /* Kernel Memory NonPaged Edit Control */
static HWND hPhysicalMemoryTotalEdit;        /* Physical Memory Total Edit Control */
static HWND hPhysicalMemoryAvailableEdit;    /* Physical Memory Available Edit Control */
static HWND hPhysicalMemorySystemCacheEdit;  /* Physical Memory System Cache Edit Control */
static HWND hTotalsHandleCountEdit;          /* Total Handles Edit Control */
static HWND hTotalsProcessCountEdit;         /* Total Processes Edit Control */
static HWND hTotalsThreadCountEdit;          /* Total Threads Edit Control */

static int nPerformancePageWidth;
static int nPerformancePageHeight;
static int lastX, lastY;

void AdjustFrameSize(HWND hCntrl, HWND hDlg, int nXDifference, int nYDifference, int pos)
{
    RECT  rc;
    int   cx, cy, sx, sy;

    GetClientRect(hCntrl, &rc);
    MapWindowPoints(hCntrl, hDlg, (LPPOINT)(PRECT)(&rc), sizeof(RECT)/sizeof(POINT));
    if (pos) {
        cx = rc.left;
        cy = rc.top;
        sx = rc.right - rc.left;
        switch (pos) {
        case 1:
            break;
        case 2:
            cy += nYDifference / 2;
            break;
        case 3:
            sx += nXDifference;
            break;
        case 4:
            cy += nYDifference / 2;
            sx += nXDifference;
            break;
        }
        sy = rc.bottom - rc.top + nYDifference / 2;
        SetWindowPos(hCntrl, NULL, cx, cy, sx, sy, SWP_NOACTIVATE|SWP_NOOWNERZORDER|SWP_NOZORDER);
    } else {
        cx = rc.left + nXDifference;
        cy = rc.top + nYDifference;
        SetWindowPos(hCntrl, NULL, cx, cy, 0, 0, SWP_NOACTIVATE|SWP_NOOWNERZORDER|SWP_NOSIZE|SWP_NOZORDER);
    }
    InvalidateRect(hCntrl, NULL, TRUE);
}

static inline
void AdjustControlPosition(HWND hCntrl, HWND hDlg, int nXDifference, int nYDifference)
{
    AdjustFrameSize(hCntrl, hDlg, nXDifference, nYDifference, 0);
}

static inline
void AdjustCntrlPos(int ctrl_id, HWND hDlg, int nXDifference, int nYDifference)
{
    AdjustFrameSize(GetDlgItem(hDlg, ctrl_id), hDlg, nXDifference, nYDifference, 0);
}

INT_PTR CALLBACK
PerformancePageWndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    RECT rc;

    switch (message)
    {
        case WM_DESTROY:
            GraphCtrl_Dispose(&PerformancePageCpuUsageHistoryGraph);
            GraphCtrl_Dispose(&PerformancePageMemUsageHistoryGraph);
            break;

        case WM_INITDIALOG:
        {
            BOOL bGraph;
            TM_FORMAT fmt;

            /* Save the width and height */
            GetClientRect(hDlg, &rc);
            nPerformancePageWidth = rc.right;
            nPerformancePageHeight = rc.bottom;

            /* Update window position */
            SetWindowPos(hDlg, NULL, 15, 30, 0, 0, SWP_NOACTIVATE|SWP_NOOWNERZORDER|SWP_NOSIZE|SWP_NOZORDER);

            /*
             * Get handles to all the controls
             */
            hTotalsFrame = GetDlgItem(hDlg, IDC_TOTALS_FRAME);
            hCommitChargeFrame = GetDlgItem(hDlg, IDC_COMMIT_CHARGE_FRAME);
            hKernelMemoryFrame = GetDlgItem(hDlg, IDC_KERNEL_MEMORY_FRAME);
            hPhysicalMemoryFrame = GetDlgItem(hDlg, IDC_PHYSICAL_MEMORY_FRAME);

            hCpuUsageFrame = GetDlgItem(hDlg, IDC_CPU_USAGE_FRAME);
            hMemUsageFrame = GetDlgItem(hDlg, IDC_MEM_USAGE_FRAME);
            hCpuUsageHistoryFrame = GetDlgItem(hDlg, IDC_CPU_USAGE_HISTORY_FRAME);
            hMemUsageHistoryFrame = GetDlgItem(hDlg, IDC_MEMORY_USAGE_HISTORY_FRAME);

            hCommitChargeTotalEdit = GetDlgItem(hDlg, IDC_COMMIT_CHARGE_TOTAL);
            hCommitChargeLimitEdit = GetDlgItem(hDlg, IDC_COMMIT_CHARGE_LIMIT);
            hCommitChargePeakEdit = GetDlgItem(hDlg, IDC_COMMIT_CHARGE_PEAK);
            hKernelMemoryTotalEdit = GetDlgItem(hDlg, IDC_KERNEL_MEMORY_TOTAL);
            hKernelMemoryPagedEdit = GetDlgItem(hDlg, IDC_KERNEL_MEMORY_PAGED);
            hKernelMemoryNonPagedEdit = GetDlgItem(hDlg, IDC_KERNEL_MEMORY_NONPAGED);
            hPhysicalMemoryTotalEdit = GetDlgItem(hDlg, IDC_PHYSICAL_MEMORY_TOTAL);
            hPhysicalMemoryAvailableEdit = GetDlgItem(hDlg, IDC_PHYSICAL_MEMORY_AVAILABLE);
            hPhysicalMemorySystemCacheEdit = GetDlgItem(hDlg, IDC_PHYSICAL_MEMORY_SYSTEM_CACHE);
            hTotalsHandleCountEdit = GetDlgItem(hDlg, IDC_TOTALS_HANDLE_COUNT);
            hTotalsProcessCountEdit = GetDlgItem(hDlg, IDC_TOTALS_PROCESS_COUNT);
            hTotalsThreadCountEdit = GetDlgItem(hDlg, IDC_TOTALS_THREAD_COUNT);

            hCpuUsageGraph = GetDlgItem(hDlg, IDC_CPU_USAGE_GRAPH);
            hMemUsageGraph = GetDlgItem(hDlg, IDC_MEM_USAGE_GRAPH);
            hPerformancePageMemUsageHistoryGraph = GetDlgItem(hDlg, IDC_MEM_USAGE_HISTORY_GRAPH);
            hPerformancePageCpuUsageHistoryGraph = GetDlgItem(hDlg, IDC_CPU_USAGE_HISTORY_GRAPH);

            /* Create the controls */
            fmt.clrBack = RGB(0, 0, 0);
            fmt.clrGrid = RGB(0, 128, 64);
            fmt.clrPlot0 = RGB(0, 255, 0);
            fmt.clrPlot1 = RGB(255, 0, 0);
            fmt.GridCellWidth = fmt.GridCellHeight = 12;
            fmt.DrawSecondaryPlot = TaskManagerSettings.ShowKernelTimes;
            bGraph = GraphCtrl_Create(&PerformancePageCpuUsageHistoryGraph, hPerformancePageCpuUsageHistoryGraph, hDlg, &fmt);
            if (!bGraph)
            {
                EndDialog(hDlg, 0);
                return FALSE;
            }

            fmt.clrPlot0 = RGB(255, 255, 0);
            fmt.clrPlot1 = RGB(100, 255, 255);
            fmt.DrawSecondaryPlot = TRUE;
            bGraph = GraphCtrl_Create(&PerformancePageMemUsageHistoryGraph, hPerformancePageMemUsageHistoryGraph, hDlg, &fmt);
            if (!bGraph)
            {
                EndDialog(hDlg, 0);
                return FALSE;
            }

            /*
             * Subclass graph buttons
             */
            OldGraphWndProc = (WNDPROC)SetWindowLongPtrW(hCpuUsageGraph, GWLP_WNDPROC, (LONG_PTR)Graph_WndProc);
            SetWindowLongPtrW(hMemUsageGraph, GWLP_WNDPROC, (LONG_PTR)Graph_WndProc);
            OldGraphCtrlWndProc = (WNDPROC)SetWindowLongPtrW(hPerformancePageMemUsageHistoryGraph, GWLP_WNDPROC, (LONG_PTR)GraphCtrl_WndProc);
            SetWindowLongPtrW(hPerformancePageCpuUsageHistoryGraph, GWLP_WNDPROC, (LONG_PTR)GraphCtrl_WndProc);
            return TRUE;
        }

        case WM_COMMAND:
            break;

        case WM_SIZE:
        {
            int  cx, cy;
            int  nXDifference;
            int  nYDifference;

            if (wParam == SIZE_MINIMIZED)
                return 0;

            cx = LOWORD(lParam);
            cy = HIWORD(lParam);
            nXDifference = cx - nPerformancePageWidth;
            nYDifference = cy - nPerformancePageHeight;
            nPerformancePageWidth = cx;
            nPerformancePageHeight = cy;

            /* Reposition the performance page's controls */
            AdjustFrameSize(hTotalsFrame, hDlg, 0, nYDifference, 0);
            AdjustFrameSize(hCommitChargeFrame, hDlg, 0, nYDifference, 0);
            AdjustFrameSize(hKernelMemoryFrame, hDlg, 0, nYDifference, 0);
            AdjustFrameSize(hPhysicalMemoryFrame, hDlg, 0, nYDifference, 0);
            AdjustCntrlPos(IDS_COMMIT_CHARGE_TOTAL, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_COMMIT_CHARGE_LIMIT, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_COMMIT_CHARGE_PEAK, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_KERNEL_MEMORY_TOTAL, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_KERNEL_MEMORY_PAGED, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_KERNEL_MEMORY_NONPAGED, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_PHYSICAL_MEMORY_TOTAL, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_PHYSICAL_MEMORY_AVAILABLE, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_PHYSICAL_MEMORY_SYSTEM_CACHE, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_TOTALS_HANDLE_COUNT, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_TOTALS_PROCESS_COUNT, hDlg, 0, nYDifference);
            AdjustCntrlPos(IDS_TOTALS_THREAD_COUNT, hDlg, 0, nYDifference);

            AdjustControlPosition(hCommitChargeTotalEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hCommitChargeLimitEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hCommitChargePeakEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hKernelMemoryTotalEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hKernelMemoryPagedEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hKernelMemoryNonPagedEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hPhysicalMemoryTotalEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hPhysicalMemoryAvailableEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hPhysicalMemorySystemCacheEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hTotalsHandleCountEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hTotalsProcessCountEdit, hDlg, 0, nYDifference);
            AdjustControlPosition(hTotalsThreadCountEdit, hDlg, 0, nYDifference);

            nXDifference += lastX;
            nYDifference += lastY;
            lastX = lastY = 0;
            if (nXDifference % 2)
            {
                if (nXDifference > 0)
                {
                    nXDifference--;
                    lastX++;
                }
                else
                {
                    nXDifference++;
                    lastX--;
                }
            }
            if (nYDifference % 2)
            {
                if (nYDifference > 0)
                {
                    nYDifference--;
                    lastY++;
                }
                else
                {
                    nYDifference++;
                    lastY--;
                }
            }
            AdjustFrameSize(hCpuUsageFrame, hDlg, nXDifference, nYDifference, 1);
            AdjustFrameSize(hMemUsageFrame, hDlg, nXDifference, nYDifference, 2);
            AdjustFrameSize(hCpuUsageHistoryFrame, hDlg, nXDifference, nYDifference, 3);
            AdjustFrameSize(hMemUsageHistoryFrame, hDlg, nXDifference, nYDifference, 4);
            AdjustFrameSize(hCpuUsageGraph, hDlg, nXDifference, nYDifference, 1);
            AdjustFrameSize(hMemUsageGraph, hDlg, nXDifference, nYDifference, 2);
            AdjustFrameSize(hPerformancePageCpuUsageHistoryGraph, hDlg, nXDifference, nYDifference, 3);
            AdjustFrameSize(hPerformancePageMemUsageHistoryGraph, hDlg, nXDifference, nYDifference, 4);
            break;
        }
    }
    return 0;
}

static void
UpdatePerfStatusBar(
    _In_ ULONG TotalProcesses,
    _In_ ULONG CpuUsage,
    _In_ ULONGLONG CommitChargeTotal,
    _In_ ULONGLONG CommitChargeLimit)
{
    static WCHAR szProcesses[256] = L"";
    static WCHAR szCpuUsage[256]  = L"";
    static WCHAR szMemUsage[256]  = L"";

    WCHAR szChargeTotalFormat[256];
    WCHAR szChargeLimitFormat[256];
    WCHAR Text[260];

    /* Do nothing if we are in the menu loop */
    if (bInMenuLoop)
        return;

    if (!*szProcesses)
        LoadStringW(hInst, IDS_STATUS_PROCESSES, szProcesses, ARRAYSIZE(szProcesses));
    if (!*szCpuUsage)
        LoadStringW(hInst, IDS_STATUS_CPUUSAGE, szCpuUsage, ARRAYSIZE(szCpuUsage));
    if (!*szMemUsage)
        LoadStringW(hInst, IDS_STATUS_MEMUSAGE, szMemUsage, ARRAYSIZE(szMemUsage));

    wsprintfW(Text, szProcesses, TotalProcesses);
    SendMessageW(hStatusWnd, SB_SETTEXT, 0, (LPARAM)Text);

    wsprintfW(Text, szCpuUsage, CpuUsage);
    SendMessageW(hStatusWnd, SB_SETTEXT, 1, (LPARAM)Text);

    StrFormatByteSizeW(CommitChargeTotal * 1024,
                       szChargeTotalFormat,
                       ARRAYSIZE(szChargeTotalFormat));

    StrFormatByteSizeW(CommitChargeLimit * 1024,
                       szChargeLimitFormat,
                       ARRAYSIZE(szChargeLimitFormat));

    wsprintfW(Text, szMemUsage, szChargeTotalFormat, szChargeLimitFormat,
              (CommitChargeLimit ? ((CommitChargeTotal * 100) / CommitChargeLimit) : 0));
    SendMessageW(hStatusWnd, SB_SETTEXT, 2, (LPARAM)Text);
}

void RefreshPerformancePage(void)
{
    ULONGLONG CommitChargeTotal;
    ULONGLONG CommitChargeLimit;
    ULONGLONG CommitChargePeak;

    ULONGLONG KernelMemoryTotal;
    ULONGLONG KernelMemoryPaged;
    ULONGLONG KernelMemoryNonPaged;

    ULONGLONG PhysicalMemoryTotal;
    ULONGLONG PhysicalMemoryAvailable;
    ULONGLONG PhysicalMemorySystemCache;

    ULONG TotalHandles;
    ULONG TotalThreads;
    ULONG TotalProcesses;

    ULONG CpuUsage;
    ULONG CpuKernelUsage;

    WCHAR Text[260];

    int nBarsUsed1;
    int nBarsUsed2;

    /*
     * Update the commit charge info
     */
    CommitChargeTotal = PerfDataGetCommitChargeTotalK();
    CommitChargeLimit = PerfDataGetCommitChargeLimitK();
    CommitChargePeak  = PerfDataGetCommitChargePeakK();
    _ui64tow(CommitChargeTotal, Text, 10);
    SetWindowTextW(hCommitChargeTotalEdit, Text);
    _ui64tow(CommitChargeLimit, Text, 10);
    SetWindowTextW(hCommitChargeLimitEdit, Text);
    _ui64tow(CommitChargePeak, Text, 10);
    SetWindowTextW(hCommitChargePeakEdit, Text);

    /*
     * Update the kernel memory info
     */
    KernelMemoryTotal = PerfDataGetKernelMemoryTotalK();
    KernelMemoryPaged = PerfDataGetKernelMemoryPagedK();
    KernelMemoryNonPaged = PerfDataGetKernelMemoryNonPagedK();
    _ui64tow(KernelMemoryTotal, Text, 10);
    SetWindowTextW(hKernelMemoryTotalEdit, Text);
    _ui64tow(KernelMemoryPaged, Text, 10);
    SetWindowTextW(hKernelMemoryPagedEdit, Text);
    _ui64tow(KernelMemoryNonPaged, Text, 10);
    SetWindowTextW(hKernelMemoryNonPagedEdit, Text);

    /*
     * Update the physical memory info
     */
    PhysicalMemoryTotal = PerfDataGetPhysicalMemoryTotalK();
    PhysicalMemoryAvailable = PerfDataGetPhysicalMemoryAvailableK();
    PhysicalMemorySystemCache = PerfDataGetPhysicalMemorySystemCacheK();
    _ui64tow(PhysicalMemoryTotal, Text, 10);
    SetWindowTextW(hPhysicalMemoryTotalEdit, Text);
    _ui64tow(PhysicalMemoryAvailable, Text, 10);
    SetWindowTextW(hPhysicalMemoryAvailableEdit, Text);
    _ui64tow(PhysicalMemorySystemCache, Text, 10);
    SetWindowTextW(hPhysicalMemorySystemCacheEdit, Text);

    /*
     * Update the totals info
     */
    TotalHandles = PerfDataGetSystemHandleCount();
    TotalThreads = PerfDataGetTotalThreadCount();
    TotalProcesses = PerfDataGetProcessCount();
    _ultow(TotalHandles, Text, 10);
    SetWindowTextW(hTotalsHandleCountEdit, Text);
    _ultow(TotalThreads, Text, 10);
    SetWindowTextW(hTotalsThreadCountEdit, Text);
    _ultow(TotalProcesses, Text, 10);
    SetWindowTextW(hTotalsProcessCountEdit, Text);

    /*
     * Get the CPU usage
     */
    CpuUsage = PerfDataGetProcessorUsage();
    CpuKernelUsage = PerfDataGetProcessorSystemUsage();

    /*
     * Update the graphs
     */
    nBarsUsed1 = CommitChargeLimit ? ((CommitChargeTotal * 100) / CommitChargeLimit) : 0;
    nBarsUsed2 = PhysicalMemoryTotal ? ((PhysicalMemoryAvailable * 100) / PhysicalMemoryTotal) : 0;
    GraphCtrl_AddPoint(&PerformancePageCpuUsageHistoryGraph, CpuUsage, CpuKernelUsage);
    GraphCtrl_AddPoint(&PerformancePageMemUsageHistoryGraph, nBarsUsed1, nBarsUsed2);

    /* Update the status bar */
    UpdatePerfStatusBar(TotalProcesses, CpuUsage, CommitChargeTotal, CommitChargeLimit);

    /** Down below, that's what we do IIF we are actually active and need to repaint stuff **/

    /*
     * Redraw the graphs
     */
    InvalidateRect(hCpuUsageGraph, NULL, FALSE);
    InvalidateRect(hMemUsageGraph, NULL, FALSE);

    InvalidateRect(hPerformancePageCpuUsageHistoryGraph, NULL, FALSE);
    InvalidateRect(hPerformancePageMemUsageHistoryGraph, NULL, FALSE);
}

void PerformancePage_OnViewShowKernelTimes(void)
{
    HMENU hMenu;
    HMENU hViewMenu;

    hMenu = GetMenu(hMainWnd);
    hViewMenu = GetSubMenu(hMenu, 2);

    /* Check or uncheck the show 16-bit tasks menu item */
    if (GetMenuState(hViewMenu, ID_VIEW_SHOWKERNELTIMES, MF_BYCOMMAND) & MF_CHECKED)
    {
        CheckMenuItem(hViewMenu, ID_VIEW_SHOWKERNELTIMES, MF_BYCOMMAND|MF_UNCHECKED);
        TaskManagerSettings.ShowKernelTimes = FALSE;
        PerformancePageCpuUsageHistoryGraph.DrawSecondaryPlot = FALSE;
    }
    else
    {
        CheckMenuItem(hViewMenu, ID_VIEW_SHOWKERNELTIMES, MF_BYCOMMAND|MF_CHECKED);
        TaskManagerSettings.ShowKernelTimes = TRUE;
        PerformancePageCpuUsageHistoryGraph.DrawSecondaryPlot = TRUE;
    }

    GraphCtrl_RedrawBitmap(&PerformancePageCpuUsageHistoryGraph, PerformancePageCpuUsageHistoryGraph.BitmapHeight);
    RefreshPerformancePage();
}

void PerformancePage_OnViewCPUHistoryOneGraphAll(void)
{
    HMENU hMenu;
    HMENU hViewMenu;
    HMENU hCPUHistoryMenu;

    hMenu = GetMenu(hMainWnd);
    hViewMenu = GetSubMenu(hMenu, 2);
    hCPUHistoryMenu = GetSubMenu(hViewMenu, 3);

    TaskManagerSettings.CPUHistory_OneGraphPerCPU = FALSE;
    CheckMenuRadioItem(hCPUHistoryMenu, ID_VIEW_CPUHISTORY_ONEGRAPHALL, ID_VIEW_CPUHISTORY_ONEGRAPHPERCPU, ID_VIEW_CPUHISTORY_ONEGRAPHALL, MF_BYCOMMAND);
}

void PerformancePage_OnViewCPUHistoryOneGraphPerCPU(void)
{
    HMENU hMenu;
    HMENU hViewMenu;
    HMENU hCPUHistoryMenu;

    hMenu = GetMenu(hMainWnd);
    hViewMenu = GetSubMenu(hMenu, 2);
    hCPUHistoryMenu = GetSubMenu(hViewMenu, 3);

    TaskManagerSettings.CPUHistory_OneGraphPerCPU = TRUE;
    CheckMenuRadioItem(hCPUHistoryMenu, ID_VIEW_CPUHISTORY_ONEGRAPHALL, ID_VIEW_CPUHISTORY_ONEGRAPHPERCPU, ID_VIEW_CPUHISTORY_ONEGRAPHPERCPU, MF_BYCOMMAND);
}
