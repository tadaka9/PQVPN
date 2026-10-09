/* SPDX-License-Identifier: MIT */
/*
 * PQVPN Tunnel Driver — bounded layer-3 data path.
 *
 * A WDM NDIS miniport that creates ONE virtual layer-3 adapter ("PQVPN
 * Tunnel") whose data path is a user-mode file object. This phase delivers:
 *
 *   - the adapter registered with ndis.sys (NdisMRegisterMiniportDriver) with
 *     safe no-op handlers;
 *   - \\.\PQVPN_TUN0 with a default-deny DACL (SYSTEM + Administrators only);
 *   - a bounded kernel-to-user packet queue;
 *   - one IP datagram per READ/WRITE operation;
 *   - NDIS send completion and receive indication with strict ownership.
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

#define PQVPN_PHASE 2
#define PQVPN_MAX_PACKET_SIZE 65536UL
#define PQVPN_MAX_QUEUED_PACKETS 1024UL
#define PQVPN_MAX_QUEUED_BYTES (16UL * 1024UL * 1024UL)
#define PQVPN_PACKET_TAG 'pkqP'

typedef struct _PQVPN_PACKET {
    LIST_ENTRY Link;
    ULONG Length;
    UCHAR Data[1];
} PQVPN_PACKET, *PPQVPN_PACKET;

typedef struct _PQVPN_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN        Closing; /* set on IRP_MJ_CLEANUP, checked by late IRPs   */
    BOOLEAN        AdapterReady;
    NDIS_HANDLE    AdapterHandle;
    NDIS_HANDLE    ReceivePool;
    ULONG          PacketFilter; /* last OID_GEN_CURRENT_PACKET_FILTER value */
    KSPIN_LOCK     QueueLock;
    LIST_ENTRY     OutboundQueue;
    ULONG          QueuedPackets;
    ULONG          QueuedBytes;
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
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (ctx && stack->MajorFunction == IRP_MJ_CREATE) ctx->Closing = FALSE;
    return pqvpn_complete(irp, STATUS_SUCCESS);
}

static NTSTATUS pqvpn_dispatch_cleanup(PDEVICE_OBJECT device, PIRP irp) {
    PPQVPN_CONTEXT ctx = (PPQVPN_CONTEXT)device->DeviceExtension;

    if (ctx) {
        ctx->Closing = TRUE;
    }
    return pqvpn_complete(irp, STATUS_SUCCESS);
}

/* There is no IRP_MJ_DELETE major function: the system deletes the device
 * object after cleanup. The context is therefore released in DriverUnload,
 * where all IRPs are guaranteed to have completed. */

static BOOLEAN pqvpn_valid_ip_packet(const UCHAR* data, ULONG length) {
    UCHAR version;
    if (data == NULL || length < 20 || length > PQVPN_MAX_PACKET_SIZE) return FALSE;
    version = (UCHAR)(data[0] >> 4);
    return (version == 4 && length >= 20) || (version == 6 && length >= 40);
}

static VOID pqvpn_free_outbound_queue(PPQVPN_CONTEXT ctx) {
    LIST_ENTRY local;
    KIRQL old_irql;
    InitializeListHead(&local);
    KeAcquireSpinLock(&ctx->QueueLock, &old_irql);
    while (!IsListEmpty(&ctx->OutboundQueue)) {
        InsertTailList(&local, RemoveHeadList(&ctx->OutboundQueue));
    }
    ctx->QueuedPackets = 0;
    ctx->QueuedBytes = 0;
    KeReleaseSpinLock(&ctx->QueueLock, old_irql);
    while (!IsListEmpty(&local)) {
        PPQVPN_PACKET packet = CONTAINING_RECORD(RemoveHeadList(&local), PQVPN_PACKET, Link);
        ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
    }
}

static NTSTATUS pqvpn_dispatch_read(PDEVICE_OBJECT device, PIRP irp) {
    PPQVPN_CONTEXT ctx = (PPQVPN_CONTEXT)device->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PPQVPN_PACKET packet = NULL;
    KIRQL old_irql;
    if (ctx == NULL || ctx->Closing || !ctx->AdapterReady) {
        return pqvpn_complete(irp, STATUS_DEVICE_NOT_READY);
    }
    KeAcquireSpinLock(&ctx->QueueLock, &old_irql);
    if (!IsListEmpty(&ctx->OutboundQueue)) {
        packet = CONTAINING_RECORD(RemoveHeadList(&ctx->OutboundQueue), PQVPN_PACKET, Link);
        ctx->QueuedPackets--;
        ctx->QueuedBytes -= packet->Length;
    }
    KeReleaseSpinLock(&ctx->QueueLock, old_irql);
    if (packet == NULL) return pqvpn_complete(irp, STATUS_NO_MORE_ENTRIES);
    if (stack->Parameters.Read.Length < packet->Length) {
        ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
        return pqvpn_complete(irp, STATUS_BUFFER_TOO_SMALL);
    }
    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, packet->Data, packet->Length);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = packet->Length;
    ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
    IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS pqvpn_dispatch_write(PDEVICE_OBJECT device, PIRP irp) {
    PPQVPN_CONTEXT ctx = (PPQVPN_CONTEXT)device->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG length = stack->Parameters.Write.Length;
    PVOID data = NULL;
    PMDL mdl = NULL;
    PNET_BUFFER_LIST nbl = NULL;
    if (ctx == NULL || ctx->Closing || !ctx->AdapterReady || ctx->ReceivePool == NULL) {
        return pqvpn_complete(irp, STATUS_DEVICE_NOT_READY);
    }
    if (!pqvpn_valid_ip_packet((const UCHAR*)irp->AssociatedIrp.SystemBuffer, length)) {
        return pqvpn_complete(irp, STATUS_INVALID_BUFFER_SIZE);
    }
    data = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, PQVPN_PACKET_TAG);
    if (data == NULL) return pqvpn_complete(irp, STATUS_INSUFFICIENT_RESOURCES);
    RtlCopyMemory(data, irp->AssociatedIrp.SystemBuffer, length);
    mdl = IoAllocateMdl(data, length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        ExFreePoolWithTag(data, PQVPN_PACKET_TAG);
        return pqvpn_complete(irp, STATUS_INSUFFICIENT_RESOURCES);
    }
    MmBuildMdlForNonPagedPool(mdl);
    nbl = NdisAllocateNetBufferAndNetBufferList(ctx->ReceivePool, 0, 0, mdl, 0, length);
    if (nbl == NULL) {
        IoFreeMdl(mdl);
        ExFreePoolWithTag(data, PQVPN_PACKET_TAG);
        return pqvpn_complete(irp, STATUS_INSUFFICIENT_RESOURCES);
    }
    nbl->SourceHandle = ctx->AdapterHandle;
    // Receive flags must be zero: with NDIS_RECEIVE_FLAGS_RESOURCES set, NDIS
    // would later hand the NBLs back to MiniportReturnNetBufferLists (a handler
    // this driver does not register), on buffers it has already freed — a
    // use-after-free in the receive data path. Without the flag the miniport
    // keeps ownership, so freeing right after the synchronous indication is
    // exactly the correct TUN pattern.
    NdisMIndicateReceiveNetBufferLists(ctx->AdapterHandle, nbl, NDIS_DEFAULT_PORT_NUMBER,
                                       1, 0);
    NdisFreeNetBufferList(nbl);
    IoFreeMdl(mdl);
    ExFreePoolWithTag(data, PQVPN_PACKET_TAG);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = length;
    IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* NDIS miniport handlers                                              */
/*                                                                     */
/* Signatures follow the NDIS 6.x miniport contract in ndis.h          */
/* (NDIS_MINIPORT_DRIVER_CHARACTERISTICS).                            */
/* adapter registers and binds cleanly; all data movement is refused   */
/* safely — SendNetBufferLists frees what it is given (never leaks),   */
/* OIDs answer a minimal set, everything else returns                  */
/* NDIS_STATUS_NOT_SUPPORTED.                                          */
/* ------------------------------------------------------------------ */

static NDIS_STATUS pqvpn_initialize_ex(
    NDIS_HANDLE adapter_handle,
    NDIS_HANDLE miniport_driver_context,
    PNDIS_MINIPORT_INIT_PARAMETERS init_parameters) {
    (void)miniport_driver_context;
    (void)init_parameters;
    if (g_Context == NULL) return NDIS_STATUS_RESOURCES;
    {
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES registration;
        NET_BUFFER_LIST_POOL_PARAMETERS pool_parameters;
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES general;
        static const UCHAR permanent_address[6] = {0x02, 0x50, 0x51, 0x56, 0x50, 0x4e};

        RtlZeroMemory(&registration, sizeof(registration));
        registration.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
        registration.Header.Revision = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
        registration.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
        registration.MiniportAdapterContext = g_Context;
        registration.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;
        registration.CheckForHangTimeInSeconds = 0;
        registration.InterfaceType = NdisInterfaceInternal;
        if (NdisMSetMiniportAttributes(adapter_handle,
                (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&registration) != NDIS_STATUS_SUCCESS) {
            return NDIS_STATUS_FAILURE;
        }

        RtlZeroMemory(&pool_parameters, sizeof(pool_parameters));
        pool_parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        pool_parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        pool_parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        pool_parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
        pool_parameters.fAllocateNetBuffer = TRUE;
        pool_parameters.PoolTag = PQVPN_PACKET_TAG;
        g_Context->ReceivePool = NdisAllocateNetBufferListPool(adapter_handle, &pool_parameters);
        if (g_Context->ReceivePool == NULL) return NDIS_STATUS_RESOURCES;

        RtlZeroMemory(&general, sizeof(general));
        general.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
        general.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
        general.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
        general.MediaType = NdisMediumIP;
        general.PhysicalMediumType = NdisPhysicalMediumUnspecified;
        general.MtuSize = 65535;
        general.MaxXmitLinkSpeed = general.MaxRcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
        general.XmitLinkSpeed = general.RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
        general.MediaConnectState = MediaConnectStateConnected;
        general.MediaDuplexState = MediaDuplexStateFull;
        general.LookaheadSize = 65535;
        general.MacOptions = NDIS_MAC_OPTION_NO_LOOPBACK;
        general.SupportedPacketFilters = 0;
        general.MaxMulticastListSize = 0;
        general.MacAddressLength = sizeof(permanent_address);
        RtlCopyMemory(general.PermanentMacAddress, permanent_address, sizeof(permanent_address));
        RtlCopyMemory(general.CurrentMacAddress, permanent_address, sizeof(permanent_address));
        general.AccessType = NET_IF_ACCESS_BROADCAST;
        general.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
        general.ConnectionType = NET_IF_CONNECTION_DEDICATED;
        general.IfType = IF_TYPE_TUNNEL;
        general.IfConnectorPresent = FALSE;
        if (NdisMSetMiniportAttributes(adapter_handle,
                (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&general) != NDIS_STATUS_SUCCESS) {
            NdisFreeNetBufferListPool(g_Context->ReceivePool);
            g_Context->ReceivePool = NULL;
            return NDIS_STATUS_FAILURE;
        }
    }
    g_Context->AdapterHandle = adapter_handle;
    g_Context->AdapterReady = TRUE;
    return NDIS_STATUS_SUCCESS;
}

static VOID pqvpn_halt(NDIS_HANDLE adapter_handle, NDIS_HALT_ACTION halt_action) {
    (void)adapter_handle;
    (void)halt_action;
    if (g_Context != NULL) {
        g_Context->AdapterReady = FALSE;
        pqvpn_free_outbound_queue(g_Context);
        if (g_Context->ReceivePool != NULL) {
            NdisFreeNetBufferListPool(g_Context->ReceivePool);
            g_Context->ReceivePool = NULL;
        }
        g_Context->AdapterHandle = NULL;
    }
}

static NDIS_STATUS pqvpn_reset(NDIS_HANDLE adapter_handle, PBOOLEAN addressing_reset) {
    (void)adapter_handle;
    if (addressing_reset != NULL) {
        *addressing_reset = FALSE;
    }
    return NDIS_STATUS_SUCCESS;
}

/* Handles the OIDs Windows actually needs a layer-3 (NdisMediumIP) interface
 * to be enabled and usable. Everything else is refused; ndis.sys tolerates
 * NOT_SUPPORTED for an inactive virtual adapter.
 *
 * OID_GEN_CURRENT_PACKET_FILTER is special-cased for both query and set: the
 * kernel sets it when the interface is enabled and a TUN that only responds
 * NOT_SUPPORTED can be left in a not-ready/error state and never pass packets.
 */
static NDIS_STATUS pqvpn_oid_request(
    NDIS_HANDLE adapter_handle,
    PNDIS_OID_REQUEST request) {
    (void)adapter_handle;

    if (request->RequestType == NdisRequestQueryInformation) {
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
            *value = 65535;
            request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
            return NDIS_STATUS_SUCCESS;
        }
        case OID_GEN_CURRENT_PACKET_FILTER: {
            PULONG value = (PULONG)request->DATA.QUERY_INFORMATION.InformationBuffer;
            if (request->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
                return NDIS_STATUS_BUFFER_TOO_SHORT;
            }
            *value = (g_Context != NULL) ? g_Context->PacketFilter : 0UL;
            request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
            return NDIS_STATUS_SUCCESS;
        }
        default:
            return NDIS_STATUS_NOT_SUPPORTED;
        }
    }

    if (request->RequestType == NdisRequestSetInformation) {
        if (request->DATA.SET_INFORMATION.Oid == OID_GEN_CURRENT_PACKET_FILTER) {
            if (request->DATA.SET_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
                return NDIS_STATUS_BUFFER_TOO_SHORT;
            }
            if (g_Context != NULL) {
                g_Context->PacketFilter =
                    *(PULONG)request->DATA.SET_INFORMATION.InformationBuffer;
            }
            request->DATA.SET_INFORMATION.BytesRead = sizeof(ULONG);
            return NDIS_STATUS_SUCCESS;
        }
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    return NDIS_STATUS_NOT_SUPPORTED;
}

static VOID pqvpn_send_nbl(
    NDIS_HANDLE adapter_handle,
    PNET_BUFFER_LIST net_buffer_list,
    NDIS_PORT_NUMBER port_number,
    ULONG send_flags) {
    (void)port_number;
    if (g_Context != NULL && g_Context->AdapterReady) {
        PNET_BUFFER_LIST nbl;
        for (nbl = net_buffer_list; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
            PNET_BUFFER nb;
            NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;
            for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
                ULONG length = NET_BUFFER_DATA_LENGTH(nb);
                PPQVPN_PACKET packet;
                PUCHAR source;
                KIRQL old_irql;
                if (length < 20 || length > PQVPN_MAX_PACKET_SIZE) {
                    NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_INVALID_LENGTH;
                    continue;
                }
                packet = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                    FIELD_OFFSET(PQVPN_PACKET, Data) + length, PQVPN_PACKET_TAG);
                source = packet == NULL ? NULL :
                    NdisGetDataBuffer(nb, length, packet->Data, 1, 0);
                if (packet == NULL || source == NULL) {
                    if (packet != NULL) ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
                    NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_RESOURCES;
                    continue;
                }
                if (source != packet->Data) RtlCopyMemory(packet->Data, source, length);
                if (!pqvpn_valid_ip_packet(packet->Data, length)) {
                    ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
                    NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_INVALID_DATA;
                    continue;
                }
                packet->Length = length;
                KeAcquireSpinLock(&g_Context->QueueLock, &old_irql);
                if (g_Context->QueuedPackets >= PQVPN_MAX_QUEUED_PACKETS ||
                    g_Context->QueuedBytes + length > PQVPN_MAX_QUEUED_BYTES) {
                    KeReleaseSpinLock(&g_Context->QueueLock, old_irql);
                    ExFreePoolWithTag(packet, PQVPN_PACKET_TAG);
                    NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_RESOURCES;
                } else {
                    InsertTailList(&g_Context->OutboundQueue, &packet->Link);
                    g_Context->QueuedPackets++;
                    g_Context->QueuedBytes += length;
                    KeReleaseSpinLock(&g_Context->QueueLock, old_irql);
                }
            }
        }
    } else {
        PNET_BUFFER_LIST nbl;
        for (nbl = net_buffer_list; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
            NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_ADAPTER_NOT_READY;
    }
    NdisMSendNetBufferListsComplete(adapter_handle, net_buffer_list,
        NDIS_TEST_SEND_AT_DISPATCH_LEVEL(send_flags) ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
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

    status = IoCreateDevice(DriverObject, sizeof(PQVPN_CONTEXT), &device_name, FILE_DEVICE_UNKNOWN,
                            0, FALSE, &device_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    device_object->SecurityDescriptor = (PSECURITY_DESCRIPTOR)g_SecurityDescriptor;
    device_object->Flags |= DO_BUFFERED_IO | DO_DEVICE_INITIALIZING;

    ctx = (PPQVPN_CONTEXT)device_object->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->DeviceObject = device_object;
    ctx->Closing = FALSE;
    ctx->AdapterReady = FALSE;
    ctx->AdapterHandle = NULL;
    ctx->ReceivePool = NULL;
    KeInitializeSpinLock(&ctx->QueueLock);
    InitializeListHead(&ctx->OutboundQueue);
    ctx->QueuedPackets = 0;
    ctx->QueuedBytes = 0;

    /* Dispatch table. */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = pqvpn_dispatch_create_close;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = pqvpn_dispatch_create_close;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = pqvpn_dispatch_cleanup;
    DriverObject->MajorFunction[IRP_MJ_READ] = pqvpn_dispatch_read;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = pqvpn_dispatch_write;

    status = IoCreateSymbolicLink(&dos_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
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

    /* InitializeEx may be called before registration returns. */
    g_DeviceObject = device_object;
    g_Context = ctx;
    status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL,
                                         &characteristics,
                                         &g_NdisMiniportDriverHandle);
    if (!NT_SUCCESS(status)) {
        g_DeviceObject = NULL;
        g_Context = NULL;
        IoDeleteSymbolicLink(&dos_name);
        IoDeleteDevice(device_object);
        return status;
    }

    /* All fallible steps are done: hand the objects to DriverUnload. */
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
        pqvpn_free_outbound_queue(g_Context);
        g_Context = NULL;
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
