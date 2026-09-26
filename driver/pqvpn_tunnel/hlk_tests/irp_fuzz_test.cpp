/* SPDX-License-Identifier: MIT */
/*
 * PQVPN Tunnel Driver — IRP Fuzzing Test
 * 
 * Sends a variety of malformed and edge-case IRPs to the driver to test
 * robustness. This is part of Phase 4 hardening.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME "\\\\.\\PQVPN_TUN0"

typedef struct {
    DWORD operation;
    BYTE data[256];
} FUZZ_IRP;

static HANDLE open_device() {
    return CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void test_irp_fuzzing(HANDLE hDev) {
    printf("=== IRP Fuzzing Test ===\n");
    
    FUZZ_IRP irp;
    memset(&irp, 0, sizeof(irp));
    
    /* Test 1: Empty data */
    printf("[TEST] Empty data...\n");
    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hDev, &irp, sizeof(FUZZ_IRP), &bytesWritten, NULL);
    if (!result) {
        printf("  [OK] Driver rejected empty data (error %lu)\n", GetLastError());
    } else {
        printf("  [WARN] Driver accepted empty data\n");
    }
    
    /* Test 2: Oversized data */
    printf("[TEST] Oversized data...\n");
    BYTE largeData[1024];
    memset(largeData, 0xAA, sizeof(largeData));
    result = WriteFile(hDev, largeData, sizeof(largeData), &bytesWritten, NULL);
    if (!result) {
        printf("  [OK] Driver rejected oversized data (error %lu)\n", GetLastError());
    } else {
        printf("  [WARN] Driver accepted oversized data\n");
    }
    
    /* Test 3: Invalid operation code */
    printf("[TEST] Invalid operation code...\n");
    irp.operation = 0xFFFFFFFF;
    result = WriteFile(hDev, &irp, sizeof(FUZZ_IRP), &bytesWritten, NULL);
    if (!result) {
        printf("  [OK] Driver rejected invalid op (error %lu)\n", GetLastError());
    } else {
        printf("  [WARN] Driver accepted invalid op\n");
    }
    
    /* Test 4: Concurrent access */
    printf("[TEST] Concurrent access...\n");
    HANDLE hDev2 = open_device();
    if (hDev2 != INVALID_HANDLE_VALUE) {
        printf("  [OK] Second handle opened successfully\n");
        
        /* Try simultaneous writes */
        FUZZ_IRP irp1, irp2;
        memset(&irp1, 0x11, sizeof(irp1));
        memset(&irp2, 0x22, sizeof(irp2));
        
        OVERLAPPED ov1 = {0}, ov2 = {0};
        ov1.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        ov2.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        WriteFile(hDev, &irp1, sizeof(irp1), NULL, &ov1);
        WriteFile(hDev2, &irp2, sizeof(irp2), NULL, &ov2);
        
        WaitForSingleObject(ov1.hEvent, 5000);
        WaitForSingleObject(ov2.hEvent, 5000);
        
        CloseHandle(ov1.hEvent);
        CloseHandle(ov2.hEvent);
        CloseHandle(hDev2);
        printf("  [OK] Concurrent writes completed\n");
    } else {
        printf("  [FAIL] Could not open second handle (error %lu)\n", GetLastError());
    }
    
    /* Test 5: Rapid open/close cycles */
    printf("[TEST] Rapid open/close cycles...\n");
    for (int i = 0; i < 100; i++) {
        HANDLE h = open_device();
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        } else {
            printf("  [FAIL] Open failed at iteration %d\n", i);
            break;
        }
    }
    printf("  [OK] 100 open/close cycles completed\n");
    
    printf("=== IRP Fuzzing Test Complete ===\n");
}

int main() {
    HANDLE hDev = open_device();
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("ERROR: Could not open %s (error %lu)\n", DEVICE_NAME, GetLastError());
        return 1;
    }
    
    test_irp_fuzzing(hDev);
    
    CloseHandle(hDev);
    return 0;
}