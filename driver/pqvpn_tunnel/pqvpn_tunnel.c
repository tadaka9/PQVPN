/* SPDX-License-Identifier: MIT */
/*
 * PQVPN Tunnel Driver — Phase 1 scaffold (see docs/windows-tunnel-adapter.md).
 *
 * A WDM NDIS miniport that creates ONE virtual layer-3 adapter ("PQVPN
 * Tunnel") whose data path is a user-mode file object. This phase delivers:
 *
 *   - the adapter registered with ndis.sys (NdisMRegisterMiniportDriver) with
 *     safe no-op handlers;
 *   - \\.\PQVPN_TUN0 with a default-deny DACL (SYSTEM + Administrators only);
 *   - CREATE/CLOSE lifecycle; READ/WRITE fail closed with STATUS_NOT_SUPPORTED
 *     until Phase 2 lands the bounded packet queues.
 *
 * No protocol logic, no crypto, no DHCP emulation: by design this driver is a
 * dumb pipe and everything interpretable stays in user space where the CTest
 * suite and the pqvpn_hard_kernel gate can reach it.
 */

#include <ntddk.h>
#include <wdm.h>
#include <ndis.h>

#define PQVPN_TUN_DEVICE_NAME L"\\Device\\PQVPN_TUN0"
#define PQVPN_TUN_DOS_NAME    L"\\DosDevices\\PQVPN_TUN0"

/* Phase 1 does not forward packets yet; user mode must treat READ/WRITE as
 * "data path not available" and fall back (fail closed) to UDP-only mode. */
#define PQVPN_PHASE 1

typedef struct _PQVPN_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN        Closing; /* set on IRP_MJ_CLEANUP, checked by late IRPs   */
} PQVPN_CONTEXT, *PPQVPN_CONTEXT;

/* The DOS device name is created with the I/O manager API (IoCreateSymbolicLink /
 * IoDeleteSymbolicLink, declared in wdm.h). This SDK's ntoskrnl import library does
 * not export the Zw* system-service variants for kernel drivers. */

static NDIS_HANDLE g_NdisMiniportDriverHandle = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL; /* freed in DriverUnload          */
static PPQVPN_CONTEXT g_Context = NULL;      /* freed in DriverUnload          */

static void pqvpn_driver_unload(PDRIVER_OBJECT driver_object);

/* ------------------------------------------------------------------ */
/* Security: default-deny DACL.                                        */
/*                                                                     */
/* Built as a static byte layout (no Rtl* dependency): two             */
/* access-allowed ACEs for SYSTEM (S-1-5-18) and BUILTIN\Administrators*/
/* (S-1-5-32-544); every other principal is denied by absence. Phase 3 */
/* adds the per-node service identity; until then the node runs        */
/* elevated, which it already needs for route installation in user     */
/* mode.                                                               */
/*                                                                     */
/* Layout (all fields naturally aligned):                              */
/*   0  SECURITY_DESCRIPTOR {Revision,Sbz1,Control}      6 bytes       */
/*   8  ACL {Rev,Sbz1,AclSize,AceCount,Sbz2}             8 bytes       */
/*  16  ACE[0] header {Rev,Flags,Mask(4),Size(4)}        10 bytes      */
/*  26  SID S-1-5-18 (1+1+8+4*1)                          14 bytes      */
/*  40  ACE[1] header                                     10 bytes     */
/*  50  SID S-1-5-32-544 (1+1+8+4*3)                      22 bytes      */
/*  72  end                                               AclSize=64   */
/* ------------------------------------------------------------------ */

#define PQVPN_SD_SIZE          72
#define PQVPN_ACE0_OFFSET      16
#define PQVPN_SID_SYSTEM_OFF   26
#define PQVPN_ACE1_OFFSET      40
#define PQVPN_SID_ADMIN_OFF    50
#define PQVPN_ACL_SIZE         64

/* Access mask for the tunnel pipe: read, write, synchronize. */
#define PQVPN_PIPE_MASK \
    (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) /* 0x50000080 */

/* SE_DACL_PRESENT is not in the kernel header set here; value is stable. */
#ifndef SE_DACL_PRESENT
#define SE_DACL_PRESENT 0x0004
#endif

static UCHAR g_SecurityDescriptor[PQVPN_SD_SIZE];

static void pqvpn_build_security_descriptor(void) {
    PUCHAR sd = g_SecurityDescriptor;

    RtlZeroMemory(sd, PQVPN_SD_SIZE);

    /* SECURITY_DESCRIPTOR: Revision 1, DACL present. */
    sd[0] = 1;                                   /* Revision               */
    sd[2] = SE_DACL_PRESENT & 0xFF;              /* Control low byte       */
    sd[3] = (SE_DACL_PRESENT >> 8) & 0xFF;       /* Control high byte      */

    /* ACL header at offset 8. */
    sd[8] = 2;                                   /* AclRevision            */
    sd[10] = PQVPN_ACL_SIZE & 0xFF;              /* AclSize low            */
    sd[11] = (PQVPN_ACL_SIZE >> 8) & 0xFF;       /* AclSize high           */
    sd[12] = 2;                                  /* AceCount low           */

    /* ACE[0]: allow SYSTEM. Header layout {Rev,Flags,Mask(4),Size(4)}.   */
    sd[PQVPN_ACE0_OFFSET] = 2;                   /* AceRevision            */
    sd[PQVPN_ACE0_OFFSET + 1] = 0;               /* AceFlags               */
    sd[PQVPN_ACE0_OFFSET + 2] = PQVPN_PIPE_MASK & 0xFF;
    sd[PQVPN_ACE0_OFFSET + 3] = (PQVPN_PIPE_MASK >> 8) & 0xFF;
    sd[PQVPN_ACE0_OFFSET + 4] = (PQVPN_PIPE_MASK >> 16) & 0xFF;
    sd[PQVPN_ACE0_OFFSET + 5] = (PQVPN_PIPE_MASK >> 24) & 0xFF;
    sd[PQVPN_ACE0_OFFSET + 6] = 10 + 14;         /* AceSize incl. SID      */

    /* SID S-1-5-18 at offset 26: Revision=1, SubAuthorityCount=1,
     * IdentifierAuthority = NT (all zero), SubAuthority[0]=18. */
    sd[PQVPN_SID_SYSTEM_OFF] = 1;                /* SidRevision            */
    sd[PQVPN_SID_SYSTEM_OFF + 1] = 1;            /* SubAuthorityCount      */
    /* bytes ..+2 ..+9: IdentifierAuthority (zero, already cleared)        */
    sd[PQVPN_SID_SYSTEM_OFF + 10] = 18;          /* SubAuthority[0] low    */

    /* ACE[1]: allow BUILTIN\Administrators. */
    sd[PQVPN_ACE1_OFFSET] = 2;                   /* AceRevision            */
    sd[PQVPN_ACE1_OFFSET + 1] = 0;               /* AceFlags               */
    sd[PQVPN_ACE1_OFFSET + 2] = PQVPN_PIPE_MASK & 0xFF;
    sd[PQVPN_ACE1_OFFSET + 3] = (PQVPN_PIPE_MASK >> 8) & 0xFF;
    sd[PQVPN_ACE1_OFFSET + 4] = (PQVPN_PIPE_MASK >> 16) & 0xFF;
    sd[PQVPN_ACE1_OFFSET + 5] = (PQVPN_PIPE_MASK >> 24) & 0xFF;
    sd[PQVPN_ACE1_OFFSET + 6] = 10 + 22;         /* AceSize incl. SID      */

    /* SID S-1-5-32-544 at offset 50: Revision=1, SubAuthorityCount=3,
     * IdentifierAuthority = NT (zero), SubAuthority={5,32,544}. */
    sd[PQVPN_SID_ADMIN_OFF] = 1;                 /* SidRevision            */
    sd[PQVPN_SID_ADMIN_OFF + 1] = 3;             /* SubAuthorityCount      */
    sd[PQVPN_SID_ADMIN_OFF + 10] = 5;            /* SubAuthority[0]        */
    sd[PQVPN_SID_ADMIN_OFF + 14] = 32;           /* SubAuthority[1]        */
    sd[PQVPN_SID_ADMIN_OFF + 18] = 544 & 0xFF;   /* SubAuthority[2] low    */
    sd[PQVPN_SID_ADMIN_OFF + 19] = (544 >> 8) & 0xFF;
}

/* ------------------------------------------------------------------ */
/* Device dispatch                                                     */
/* ------------------------------------------------------------------ */

/* Dispatch contract (per WDM and working NDIS drivers): set IoStatus, call
 * IoCompleteRequest, then return the same status. */
static NTSTATUS pqvpn_complete(PIRP irp, NTSTATUS status) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS pqvpn_dispatch_create_close(PDEVICE_OBJECT device, PIRP irp) {
    PPQVPN_CONTEXT ctx = (PPQVPN_CONTEXT)device->DeviceExtension;

    if (ctx && ctx->Closing) {
        return pqvpn_complete(irp, STATUS_DEVICE_NOT_READY);
    }
    /* Phase 1: no per-handle state to allocate. */
    return pqvpn_complete(irp, STATUS_SUCCESS);
}

static NTSTATUS pqvpn_dispatch_cleanup(PDEVICE_OBJECT device, PIRP irp) {
    PPQVPN_CONTEXT ctx = (PPQVPN_CONTEXT)device->DeviceExtension;

    if (ctx) {
        ctx->Closing = TRUE; /* late READ/WRITE must fail closed            */
    }
    return pqvpn_complete(irp, STATUS_SUCCESS);
}

/* There is no IRP_MJ_DELETE major function: the system deletes the device
 * object after cleanup. The context is therefore released in DriverUnload,
 * where all IRPs are guaranteed to have completed. */

static NTSTATUS pqvpn_dispatch_not_supported(PDEVICE_OBJECT device, PIRP irp) {
    /* Phase 1 has no data path: fail closed with an unambiguous status so a
     * user-mode backend can distinguish "not built yet" from I/O errors. */
    (void)device;
    return pqvpn_complete(irp, STATUS_NOT_SUPPORTED);
}

/* ------------------------------------------------------------------ */
/* NDIS miniport handlers                                              */
/*                                                                     */
/* Signatures follow the NDIS 6.x miniport contract in ndis.h          */
/* (NDIS_MINIPORT_DRIVER_CHARACTERISTICS). Phase 1 contract: the       */
/* adapter registers and binds cleanly; all data movement is refused   */
/* safely — SendNetBufferLists frees what it is given (never leaks),   */
/* OIDs answer a minimal set, everything else returns                  */
/* NDIS_STATUS_NOT_SUPPORTED.                                          */
/* ------------------------------------------------------------------ */

static NDIS_STATUS pqvpn_initialize_ex(
    NDIS_HANDLE adapter_handle,
    NDIS_HANDLE miniport_driver_context,
    PNDIS_MINIPORT_INIT_PARAMETERS init_parameters) {
    (void)adapter_handle;
    (void)miniport_driver_context;
    (void)init_parameters;
    /* Phase 1: nothing to allocate per adapter. */
    return NDIS_STATUS_SUCCESS;
}

static VOID pqvpn_halt(NDIS_HANDLE adapter_handle, NDIS_HALT_ACTION halt_action) {
    (void)adapter_handle;
    (void)halt_action;
}

static NDIS_STATUS pqvpn_reset(NDIS_HANDLE adapter_handle, PBOOLEAN addressing_reset) {
    (void)adapter_handle;
    if (addressing_reset != NULL) {
        *addressing_reset = FALSE;
    }
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS pqvpn_oid_request(
    NDIS_HANDLE adapter_handle,
    PNDIS_OID_REQUEST request) {
    (void)adapter_handle;

    if (request->RequestType != NdisRequestQueryInformation) {
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    switch (request->DATA.QUERY_INFORMATION.Oid) {
    case OID_GEN_MEDIA_IN_USE: {
        /* Must match *MediaType in the INF (NdisMediumIP, layer-3 TUN). */
        PULONG value = (PULONG)request->DATA.QUERY_INFORMATION.InformationBuffer;
        if (request->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        *value = NdisMediumIP;
        request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
        return NDIS_STATUS_SUCCESS;
    }
    case OID_GEN_MAXIMUM_FRAME_SIZE: {
        PULONG value = (PULONG)request->DATA.QUERY_INFORMATION.InformationBuffer;
        if (request->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        *value = 65536; /* generous ceiling; Phase 2 enforces real bounds */
        request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
        return NDIS_STATUS_SUCCESS;
    }
    default:
        /* Unknown OIDs are refused; ndis.sys tolerates NOT_SUPPORTED for a
         * virtual adapter whose data path is not active yet. */
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}

/* Free everything the stack handed us: a miniport that queues nothing must
 * still release every NetBufferList it receives (no leaks, no BSOD). */
static VOID pqvpn_send_nbl(
    NDIS_HANDLE adapter_handle,
    PNET_BUFFER_LIST net_buffer_list,
    NDIS_PORT_NUMBER port_number,
    ULONG send_flags) {
    (void)adapter_handle;
    (void)port_number;
    (void)send_flags;
    if (net_buffer_list != NULL) {
        NdisFreeNetBufferList(net_buffer_list); /* one argument in this SDK */
    }
}

static VOID pqvpn_unload(PDRIVER_OBJECT driver_object) {
    /* ndis-side unload hook: real cleanup happens in DriverUnload below. */
    (void)driver_object;
}

/* ------------------------------------------------------------------ */
/* Driver entry / unload                                               */
/* ------------------------------------------------------------------ */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PDEVICE_OBJECT device_object = NULL;
    PPQVPN_CONTEXT ctx = NULL;
    UNICODE_STRING device_name, dos_name;
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS characteristics;
    NTSTATUS       status;

    RtlInitUnicodeString(&device_name, PQVPN_TUN_DEVICE_NAME);
    RtlInitUnicodeString(&dos_name, PQVPN_TUN_DOS_NAME);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    /* Default-deny DACL: only SYSTEM and Administrators may open the pipe. */
    pqvpn_build_security_descriptor();

    status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
                            0, FALSE, &device_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    device_object->SecurityDescriptor = (PSECURITY_DESCRIPTOR)g_SecurityDescriptor;
    device_object->Flags |= DO_BUFFERED_IO | DO_DEVICE_INITIALIZING;

    ctx = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PQVPN_CONTEXT), 'nvqP');
    if (ctx == NULL) {
        IoDeleteDevice(device_object);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ctx->DeviceObject = device_object;
    ctx->Closing = FALSE;
    device_object->DeviceExtension = ctx;

    /* Dispatch table. */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = pqvpn_dispatch_create_close;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = pqvpn_dispatch_create_close;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = pqvpn_dispatch_cleanup;
    DriverObject->MajorFunction[IRP_MJ_READ] = pqvpn_dispatch_not_supported;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = pqvpn_dispatch_not_supported;

    status = IoCreateSymbolicLink(&dos_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        ExFreePoolWithTag(ctx, 'nvqP');
        return status;
    }

    /* NDIS miniport registration (NDIS 6.20 contract). */
    RtlZeroMemory(&characteristics, sizeof(characteristics));
    characteristics.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
#if defined(NDIS_SUPPORT_NDIS61)
    characteristics.Header.Revision =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
#else
    characteristics.Header.Revision =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
#endif
    characteristics.Header.Size = sizeof(characteristics);
    characteristics.MajorNdisVersion = 6;
    characteristics.MinorNdisVersion = 20;
    characteristics.MajorDriverVersion = 0;
    characteristics.MinorDriverVersion = PQVPN_PHASE;
    characteristics.Flags = 0;
    characteristics.InitializeHandlerEx = pqvpn_initialize_ex;
    characteristics.HaltHandlerEx = pqvpn_halt;
    characteristics.UnloadHandler = pqvpn_unload;
    characteristics.ResetHandlerEx = pqvpn_reset;
    characteristics.OidRequestHandler = pqvpn_oid_request;
    characteristics.SendNetBufferListsHandler = pqvpn_send_nbl;

    status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL,
                                         &characteristics,
                                         &g_NdisMiniportDriverHandle);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&dos_name);
        IoDeleteDevice(device_object);
        ExFreePoolWithTag(ctx, 'nvqP');
        return status;
    }

    /* All fallible steps are done: hand the objects to DriverUnload. */
    g_DeviceObject = device_object;
    g_Context = ctx;

    DriverObject->DriverUnload = pqvpn_driver_unload;

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static void pqvpn_driver_unload(PDRIVER_OBJECT driver_object) {
    UNICODE_STRING dos_name;

    (void)driver_object;

    if (g_NdisMiniportDriverHandle != NULL) {
        NdisMDeregisterMiniportDriver(g_NdisMiniportDriverHandle);
        g_NdisMiniportDriverHandle = NULL;
    }

    RtlInitUnicodeString(&dos_name, PQVPN_TUN_DOS_NAME);
    IoDeleteSymbolicLink(&dos_name);

    /* All IRPs have completed by unload time: release the context and the
     * device object. */
    if (g_Context != NULL) {
        ExFreePoolWithTag(g_Context, 'nvqP');
        g_Context = NULL;
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
