// Windows UDE/KMDF virtual FIDO HID transport. Build with the Windows Driver Kit.

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbioctl.h>
#include <wdfusb.h>
#include <Udecx.h>
#include "ghost_fido_ude_protocol.h"

#ifndef GHOST_FIDO_VENDOR_ID
#define GHOST_FIDO_VENDOR_ID 0x0000
#endif
#ifndef GHOST_FIDO_PRODUCT_ID
#define GHOST_FIDO_PRODUCT_ID 0x0000
#endif

#define GHOST_FIDO_REPORT_SIZE 64
#define GHOST_FIDO_USB_SPEED UdecxUsbFullSpeed
#define GHOST_FIDO_REPORT_QUEUE_CAPACITY 16
#define GHOST_FIDO_ENDPOINT_CONTROL 0x00
#define GHOST_FIDO_ENDPOINT_INPUT 0x81
#define GHOST_FIDO_ENDPOINT_OUTPUT 0x01

typedef struct _GHOST_FIDO_DEVICE_CONTEXT {
    PUDECXUSBDEVICE_INIT DeviceInit;
    UDECXUSBDEVICE UsbDevice;
    UDECXUSBENDPOINT ControlEndpoint;
    UDECXUSBENDPOINT InputEndpoint;
    UDECXUSBENDPOINT OutputEndpoint;
    WDFSPINLOCK ReportLock;
    WDFSPINLOCK CompletionLock;
    WDFDPC CompletionDpc;
    WDFQUEUE InputPendingQueue;
    LIST_ENTRY DeferredCompletions;
    UCHAR InputReports[GHOST_FIDO_REPORT_QUEUE_CAPACITY][GHOST_FIDO_REPORT_SIZE];
    ULONG InputReportHead;
    ULONG InputReportCount;
    UCHAR OutputReports[GHOST_FIDO_REPORT_QUEUE_CAPACITY][GHOST_FIDO_REPORT_SIZE];
    ULONG OutputReportHead;
    ULONG OutputReportCount;
} GHOST_FIDO_DEVICE_CONTEXT, *PGHOST_FIDO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GHOST_FIDO_DEVICE_CONTEXT,
                                   GhostFidoGetDeviceContext)

typedef struct _GHOST_FIDO_ENDPOINT_QUEUE_CONTEXT {
    UCHAR EndpointAddress;
} GHOST_FIDO_ENDPOINT_QUEUE_CONTEXT, *PGHOST_FIDO_ENDPOINT_QUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GHOST_FIDO_ENDPOINT_QUEUE_CONTEXT,
                                   GhostFidoGetEndpointQueueContext)

typedef struct _GHOST_FIDO_URB_REQUEST_CONTEXT {
    LIST_ENTRY ListEntry;
    WDFREQUEST Request;
    NTSTATUS CompletionStatus;
    ULONG BytesCompleted;
    BOOLEAN CompletionQueued;
} GHOST_FIDO_URB_REQUEST_CONTEXT, *PGHOST_FIDO_URB_REQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GHOST_FIDO_URB_REQUEST_CONTEXT,
                                   GhostFidoGetUrbRequestContext)

typedef struct _GHOST_FIDO_DPC_CONTEXT {
    WDFDEVICE Device;
} GHOST_FIDO_DPC_CONTEXT, *PGHOST_FIDO_DPC_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GHOST_FIDO_DPC_CONTEXT,
                                   GhostFidoGetDpcContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD GhostFidoEvtDeviceAdd;
EVT_WDF_DEVICE_CONTEXT_CLEANUP GhostFidoEvtDeviceContextCleanup;
EVT_WDF_DPC GhostFidoDeferredUrbCompletionDpc;
EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY GhostFidoQueryUsbCapability;
EVT_UDECX_USB_DEVICE_D0_ENTRY GhostFidoDeviceD0Entry;
EVT_UDECX_USB_DEVICE_D0_EXIT GhostFidoDeviceD0Exit;
EVT_UDECX_USB_ENDPOINT_RESET GhostFidoResetEndpoint;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL GhostFidoEndpointIoctl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE GhostFidoEndpointIoctlCanceled;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL GhostFidoEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE GhostFidoInputQueueCanceled;

// FIDO Alliance usage page 0xF1D0, CTAPHID usage 0x01, 64-byte IN/OUT.
static const UCHAR GhostFidoReportDescriptor[] = {
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, GHOST_FIDO_REPORT_SIZE, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, GHOST_FIDO_REPORT_SIZE, 0x91, 0x02,
    0xC0,
};

static const UCHAR GhostFidoDeviceDescriptor[] = {
    18, USB_DEVICE_DESCRIPTOR_TYPE,
    0x00, 0x02,                         // USB 2.0
    0x00, 0x00, 0x00,                   // Class is defined by the interface
    64,                                 // Endpoint zero maximum packet size
    (UCHAR)(GHOST_FIDO_VENDOR_ID & 0xff),
    (UCHAR)((GHOST_FIDO_VENDOR_ID >> 8) & 0xff),
    (UCHAR)(GHOST_FIDO_PRODUCT_ID & 0xff),
    (UCHAR)((GHOST_FIDO_PRODUCT_ID >> 8) & 0xff),
    0x00, 0x01,                         // Device release 1.00
    0, 0, 0,                            // No unassigned identity strings
    1,                                  // One configuration
};

// One FIDO HID interface with 64-byte interrupt IN and OUT endpoints.
static const UCHAR GhostFidoConfigurationDescriptor[] = {
    9, USB_CONFIGURATION_DESCRIPTOR_TYPE,
    41, 0,                              // Total descriptor-set length
    1, 1, 0, 0x80, 50,                 // One bus-powered configuration
    9, USB_INTERFACE_DESCRIPTOR_TYPE,
    0, 0, 2,                            // Interface 0, alternate 0, two endpoints
    0x03, 0x00, 0x00, 0,               // HID, no boot subclass or protocol
    9, 0x21,                            // HID descriptor
    0x11, 0x01, 0, 1, 0x22,
    (UCHAR)(sizeof(GhostFidoReportDescriptor) & 0xff),
    (UCHAR)((sizeof(GhostFidoReportDescriptor) >> 8) & 0xff),
    7, USB_ENDPOINT_DESCRIPTOR_TYPE,
    0x81, 0x03, GHOST_FIDO_REPORT_SIZE, 0, 5,
    7, USB_ENDPOINT_DESCRIPTOR_TYPE,
    0x01, 0x03, GHOST_FIDO_REPORT_SIZE, 0, 5,
};

static NTSTATUS
GhostFidoInitializeReportQueues(_In_ WDFDEVICE Device)
{
    NTSTATUS status;
    PGHOST_FIDO_DEVICE_CONTEXT context;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_DPC_CONFIG dpcConfig;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFDPC dpc;
    WDFQUEUE queue;
    PGHOST_FIDO_DPC_CONTEXT dpcContext;

    context = GhostFidoGetDeviceContext(Device);
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Device;
    status = WdfSpinLockCreate(&attributes, &context->ReportLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfSpinLockCreate(&attributes, &context->CompletionLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeListHead(&context->DeferredCompletions);

    WDF_DPC_CONFIG_INIT(&dpcConfig, GhostFidoDeferredUrbCompletionDpc);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,
                                            GHOST_FIDO_DPC_CONTEXT);
    attributes.ParentObject = Device;
    status = WdfDpcCreate(&dpcConfig, &attributes, &dpc);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    dpcContext = GhostFidoGetDpcContext(dpc);
    dpcContext->Device = Device;
    context->CompletionDpc = dpc;

    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.EvtIoCanceledOnQueue = GhostFidoInputQueueCanceled;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Device;
    status = WdfIoQueueCreate(Device, &queueConfig, &attributes, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    context->InputPendingQueue = queue;
    return STATUS_SUCCESS;
}

static NTSTATUS
GhostFidoGetOrCreateUrbContext(_In_ WDFREQUEST Request,
                              _Out_ PGHOST_FIDO_URB_REQUEST_CONTEXT *RequestContext)
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,
                                            GHOST_FIDO_URB_REQUEST_CONTEXT);
    status = WdfObjectAllocateContext(Request, &attributes,
                                      (PVOID *)RequestContext);
    if (status == STATUS_OBJECT_NAME_EXISTS) {
        *RequestContext = GhostFidoGetUrbRequestContext(Request);
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(*RequestContext, sizeof(**RequestContext));
    InitializeListHead(&(*RequestContext)->ListEntry);
    (*RequestContext)->Request = Request;
    return STATUS_SUCCESS;
}

static VOID
GhostFidoDeferUrbCompletion(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
                            _In_ NTSTATUS CompletionStatus,
                            _In_ ULONG BytesCompleted)
{
    NTSTATUS status;
    PGHOST_FIDO_DEVICE_CONTEXT deviceContext;
    PGHOST_FIDO_URB_REQUEST_CONTEXT requestContext;
    BOOLEAN shouldEnqueue;

    deviceContext = GhostFidoGetDeviceContext(Device);
    status = GhostFidoGetOrCreateUrbContext(Request, &requestContext);
    if (!NT_SUCCESS(status)) {
        // A UDE URB must not be completed inline. The request remains owned by
        // KMDF and device teardown will cancel it if allocation is exhausted.
        return;
    }

    WdfSpinLockAcquire(deviceContext->CompletionLock);
    shouldEnqueue = !requestContext->CompletionQueued;
    if (shouldEnqueue) {
        requestContext->CompletionQueued = TRUE;
        requestContext->CompletionStatus = CompletionStatus;
        requestContext->BytesCompleted = BytesCompleted;
        InsertTailList(&deviceContext->DeferredCompletions,
                       &requestContext->ListEntry);
    }
    WdfSpinLockRelease(deviceContext->CompletionLock);
    if (shouldEnqueue) {
        (VOID)WdfDpcEnqueue(deviceContext->CompletionDpc);
    }
}

VOID
GhostFidoDeferredUrbCompletionDpc(_In_ WDFDPC Dpc)
{
    PGHOST_FIDO_DPC_CONTEXT dpcContext;
    PGHOST_FIDO_DEVICE_CONTEXT deviceContext;
    PLIST_ENTRY entry;
    PGHOST_FIDO_URB_REQUEST_CONTEXT requestContext;

    dpcContext = GhostFidoGetDpcContext(Dpc);
    deviceContext = GhostFidoGetDeviceContext(dpcContext->Device);
    for (;;) {
        WdfSpinLockAcquire(deviceContext->CompletionLock);
        if (IsListEmpty(&deviceContext->DeferredCompletions)) {
            WdfSpinLockRelease(deviceContext->CompletionLock);
            break;
        }
        entry = RemoveHeadList(&deviceContext->DeferredCompletions);
        requestContext = CONTAINING_RECORD(
            entry, GHOST_FIDO_URB_REQUEST_CONTEXT, ListEntry);
        InitializeListHead(&requestContext->ListEntry);
        WdfSpinLockRelease(deviceContext->CompletionLock);

        if (NT_SUCCESS(requestContext->CompletionStatus) &&
            requestContext->BytesCompleted != 0) {
            UdecxUrbSetBytesCompleted(requestContext->Request,
                                      requestContext->BytesCompleted);
        }
        UdecxUrbCompleteWithNtStatus(requestContext->Request,
                                     requestContext->CompletionStatus);
    }
}

static BOOLEAN
GhostFidoPushReport(_In_ WDFDEVICE Device, _In_ BOOLEAN InputReport,
                    _In_reads_(GHOST_FIDO_REPORT_SIZE) const UCHAR *Report)
{
    PGHOST_FIDO_DEVICE_CONTEXT context;
    ULONG *head;
    ULONG *count;
    UCHAR(*queue)[GHOST_FIDO_REPORT_SIZE];
    ULONG tail;
    BOOLEAN inserted;

    context = GhostFidoGetDeviceContext(Device);
    WdfSpinLockAcquire(context->ReportLock);
    if (InputReport) {
        head = &context->InputReportHead;
        count = &context->InputReportCount;
        queue = context->InputReports;
    } else {
        head = &context->OutputReportHead;
        count = &context->OutputReportCount;
        queue = context->OutputReports;
    }

    inserted = *count < GHOST_FIDO_REPORT_QUEUE_CAPACITY;
    if (inserted) {
        tail = (*head + *count) % GHOST_FIDO_REPORT_QUEUE_CAPACITY;
        RtlCopyMemory(queue[tail], Report, GHOST_FIDO_REPORT_SIZE);
        ++(*count);
    }
    WdfSpinLockRelease(context->ReportLock);
    return inserted;
}

static BOOLEAN
GhostFidoPopReport(_In_ WDFDEVICE Device, _In_ BOOLEAN InputReport,
                   _Out_writes_(GHOST_FIDO_REPORT_SIZE) UCHAR *Report)
{
    PGHOST_FIDO_DEVICE_CONTEXT context;
    ULONG *head;
    ULONG *count;
    UCHAR(*queue)[GHOST_FIDO_REPORT_SIZE];
    BOOLEAN available;

    context = GhostFidoGetDeviceContext(Device);
    WdfSpinLockAcquire(context->ReportLock);
    if (InputReport) {
        head = &context->InputReportHead;
        count = &context->InputReportCount;
        queue = context->InputReports;
    } else {
        head = &context->OutputReportHead;
        count = &context->OutputReportCount;
        queue = context->OutputReports;
    }

    available = *count != 0;
    if (available) {
        RtlCopyMemory(Report, queue[*head], GHOST_FIDO_REPORT_SIZE);
        *head = (*head + 1) % GHOST_FIDO_REPORT_QUEUE_CAPACITY;
        --(*count);
    }
    WdfSpinLockRelease(context->ReportLock);
    return available;
}

static VOID
GhostFidoResetReportQueues(_In_ WDFDEVICE Device)
{
    PGHOST_FIDO_DEVICE_CONTEXT context;

    context = GhostFidoGetDeviceContext(Device);
    if (context->ReportLock == WDF_NO_HANDLE) {
        return;
    }
    WdfSpinLockAcquire(context->ReportLock);
    context->InputReportHead = 0;
    context->InputReportCount = 0;
    context->OutputReportHead = 0;
    context->OutputReportCount = 0;
    RtlZeroMemory(context->InputReports, sizeof(context->InputReports));
    RtlZeroMemory(context->OutputReports, sizeof(context->OutputReports));
    WdfSpinLockRelease(context->ReportLock);
}

static BOOLEAN
GhostFidoHasConfiguredIdentity(VOID)
{
    return (GHOST_FIDO_VENDOR_ID != 0 &&
            GHOST_FIDO_VENDOR_ID < 0xffff &&
            GHOST_FIDO_PRODUCT_ID != 0 &&
            GHOST_FIDO_PRODUCT_ID < 0xffff);
}

static NTSTATUS
GhostFidoCreateEndpoint(_In_ WDFDEVICE Device,
                        _In_ UDECXUSBDEVICE UsbDevice,
                        _In_ UCHAR EndpointAddress,
                        _Out_ UDECXUSBENDPOINT *Endpoint)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    WDFQUEUE queue;
    PUDECXUSBENDPOINT_INIT endpointInit;
    UDECX_USB_ENDPOINT_CALLBACKS callbacks;
    PGHOST_FIDO_ENDPOINT_QUEUE_CONTEXT queueContext;

    endpointInit = UdecxUsbSimpleEndpointInitAllocate(UsbDevice);
    if (endpointInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UdecxUsbEndpointInitSetEndpointAddress(endpointInit, EndpointAddress);
    UDECX_USB_ENDPOINT_CALLBACKS_INIT(&callbacks, GhostFidoResetEndpoint);
    UdecxUsbEndpointInitSetCallbacks(endpointInit, &callbacks);

    status = UdecxUsbEndpointCreate(&endpointInit,
                                    WDF_NO_OBJECT_ATTRIBUTES,
                                    Endpoint);
    if (!NT_SUCCESS(status)) {
        UdecxUsbEndpointInitFree(endpointInit);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoInternalDeviceControl = GhostFidoEndpointIoctl;
    queueConfig.EvtIoCanceledOnQueue = GhostFidoEndpointIoctlCanceled;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
        &queueAttributes, GHOST_FIDO_ENDPOINT_QUEUE_CONTEXT);
    queueAttributes.ParentObject = Device;
    status = WdfIoQueueCreate(Device, &queueConfig, &queueAttributes, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queueContext = GhostFidoGetEndpointQueueContext(queue);
    queueContext->EndpointAddress = EndpointAddress;
    UdecxUsbEndpointSetWdfIoQueue(*Endpoint, queue);
    return STATUS_SUCCESS;
}

static NTSTATUS
GhostFidoCreateAndPlugInVirtualDevice(_In_ WDFDEVICE Device)
{
    NTSTATUS status;
    PGHOST_FIDO_DEVICE_CONTEXT context;
    WDF_OBJECT_ATTRIBUTES attributes;
    UDECX_USB_DEVICE_STATE_CHANGE_CALLBACKS callbacks;
    UDECX_USB_DEVICE_PLUG_IN_OPTIONS plugInOptions;

    context = GhostFidoGetDeviceContext(Device);
    if (context->UsbDevice != WDF_NO_HANDLE) {
        return STATUS_SUCCESS;
    }
    if (!GhostFidoHasConfiguredIdentity()) {
        // A build without explicitly assigned VID/PID keeps the controller only.
        return STATUS_NOT_SUPPORTED;
    }

    context->DeviceInit = UdecxUsbDeviceInitAllocate(Device);
    if (context->DeviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UDECX_USB_DEVICE_CALLBACKS_INIT(&callbacks);
    callbacks.EvtUsbDeviceLinkPowerEntry = GhostFidoDeviceD0Entry;
    callbacks.EvtUsbDeviceLinkPowerExit = GhostFidoDeviceD0Exit;
    UdecxUsbDeviceInitSetStateChangeCallbacks(context->DeviceInit, &callbacks);
    UdecxUsbDeviceInitSetSpeed(context->DeviceInit, GHOST_FIDO_USB_SPEED);
    UdecxUsbDeviceInitSetEndpointsType(context->DeviceInit,
                                       UdecxEndpointTypeSimple);

    status = UdecxUsbDeviceInitAddDescriptor(
        context->DeviceInit, (PUCHAR)GhostFidoDeviceDescriptor,
        sizeof(GhostFidoDeviceDescriptor));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = UdecxUsbDeviceInitAddDescriptor(
        context->DeviceInit, (PUCHAR)GhostFidoConfigurationDescriptor,
        sizeof(GhostFidoConfigurationDescriptor));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = UdecxUsbDeviceCreate(&context->DeviceInit, &attributes,
                                  &context->UsbDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = GhostFidoCreateEndpoint(Device, context->UsbDevice, 0,
                                     &context->ControlEndpoint);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoCreateEndpoint(Device, context->UsbDevice, 0x81,
                                     &context->InputEndpoint);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoCreateEndpoint(Device, context->UsbDevice, 0x01,
                                     &context->OutputEndpoint);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    GhostFidoResetReportQueues(Device);
    WdfIoQueueStart(context->InputPendingQueue);
    UDECX_USB_DEVICE_PLUG_IN_OPTIONS_INIT(&plugInOptions);
    status = UdecxUsbDevicePlugIn(context->UsbDevice, &plugInOptions);
    return status;
}

static NTSTATUS
GhostFidoDestroyVirtualDevice(_In_ WDFDEVICE Device)
{
    NTSTATUS status;
    PGHOST_FIDO_DEVICE_CONTEXT context;

    context = GhostFidoGetDeviceContext(Device);
    if (context->InputPendingQueue != WDF_NO_HANDLE) {
        WdfIoQueuePurgeSynchronously(context->InputPendingQueue);
    }
    KeFlushQueuedDpcs();

    if (context->UsbDevice != WDF_NO_HANDLE) {
        status = UdecxUsbDevicePlugOutAndDelete(context->UsbDevice);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        context->UsbDevice = WDF_NO_HANDLE;
        context->ControlEndpoint = WDF_NO_HANDLE;
        context->InputEndpoint = WDF_NO_HANDLE;
        context->OutputEndpoint = WDF_NO_HANDLE;
    }

    if (context->DeviceInit != NULL) {
        UdecxUsbDeviceInitFree(context->DeviceInit);
        context->DeviceInit = NULL;
    }
    KeFlushQueuedDpcs();
    GhostFidoResetReportQueues(Device);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, GhostFidoEvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath,
                           WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}

NTSTATUS
GhostFidoEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    UDECX_WDF_DEVICE_CONFIG controllerConfig;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    UNICODE_STRING securityDescriptor;
    PGHOST_FIDO_DEVICE_CONTEXT context;

    UNREFERENCED_PARAMETER(Driver);

    RtlInitUnicodeString(&deviceName, L"\\Device\\GhostFidoUde");
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&securityDescriptor,
                         L"D:P(A;;GRGW;;;IU)(A;;GA;;;SY)(A;;GA;;;BA)");
    status = WdfDeviceInitAssignSDDLString(DeviceInit, &securityDescriptor);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = UdecxInitializeWdfDeviceInit(DeviceInit);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,
                                            GHOST_FIDO_DEVICE_CONTEXT);
    attributes.EvtCleanupCallback = GhostFidoEvtDeviceContextCleanup;
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    context = GhostFidoGetDeviceContext(device);
    RtlZeroMemory(context, sizeof(*context));

    status = GhostFidoInitializeReportQueues(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\GhostFidoUde");
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UDECX_WDF_DEVICE_CONFIG_INIT(&controllerConfig,
                                 GhostFidoQueryUsbCapability);
    status = UdecxWdfDeviceAddUsbDeviceEmulation(device, &controllerConfig);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
                                          WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = GhostFidoEvtIoDeviceControl;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfIoQueueCreate(device, &queueConfig,
                              &attributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // The controller starts independently. The desktop app attaches the
    // virtual device only after the explicit attach operation.
    return STATUS_SUCCESS;
}

VOID
GhostFidoEvtDeviceContextCleanup(_In_ WDFOBJECT Object)
{
    WDFDEVICE device;
    PGHOST_FIDO_DEVICE_CONTEXT context;

    device = (WDFDEVICE)Object;
    context = GhostFidoGetDeviceContext(device);

    // UDE plug-out and queue purge require PASSIVE_LEVEL; WDF device cleanup
    // runs there, after the controller's endpoint requests are drained.
    (VOID)GhostFidoDestroyVirtualDevice(device);
    if (context->DeviceInit != NULL) {
        UdecxUsbDeviceInitFree(context->DeviceInit);
        context->DeviceInit = NULL;
    }
}

NTSTATUS
GhostFidoQueryUsbCapability(_In_ WDFDEVICE Device,
                            _In_ PGUID CapabilityType,
                            _In_ ULONG OutputBufferLength,
                            _Out_writes_to_opt_(OutputBufferLength, *ResultLength) PVOID OutputBuffer,
                            _Out_ PULONG ResultLength)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(CapabilityType);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    *ResultLength = 0;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS
GhostFidoValidateRequestHeader(_In_ ULONG Size, _In_ ULONG ProtocolMajor,
                              _In_ ULONG ProtocolMinor,
                              _In_ size_t InputBufferLength,
                              _In_ size_t ExpectedSize)
{
    if (InputBufferLength != ExpectedSize ||
        Size != (ULONG)ExpectedSize) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ProtocolMajor != GHOST_FIDO_UDE_PROTOCOL_MAJOR ||
        ProtocolMinor > GHOST_FIDO_UDE_PROTOCOL_MINOR) {
        return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
GhostFidoHandleAttach(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
                      _In_ size_t InputBufferLength,
                      _In_ size_t OutputBufferLength)
{
    NTSTATUS status;
    GHOST_FIDO_UDE_OPERATION_REQUEST *operationRequest;

    if (OutputBufferLength != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*operationRequest),
                                          (PVOID *)&operationRequest, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoValidateRequestHeader(operationRequest->Size,
                                            operationRequest->ProtocolMajor,
                                            operationRequest->ProtocolMinor,
                                            InputBufferLength,
                                            sizeof(*operationRequest));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (operationRequest->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = GhostFidoCreateAndPlugInVirtualDevice(Device);
    if (!NT_SUCCESS(status)) {
        (VOID)GhostFidoDestroyVirtualDevice(Device);
    }
    return status;
}

static NTSTATUS
GhostFidoHandleDetach(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
                      _In_ size_t InputBufferLength,
                      _In_ size_t OutputBufferLength)
{
    NTSTATUS status;
    GHOST_FIDO_UDE_OPERATION_REQUEST *operationRequest;

    if (OutputBufferLength != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*operationRequest),
                                          (PVOID *)&operationRequest, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoValidateRequestHeader(operationRequest->Size,
                                            operationRequest->ProtocolMajor,
                                            operationRequest->ProtocolMinor,
                                            InputBufferLength,
                                            sizeof(*operationRequest));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (operationRequest->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return GhostFidoDestroyVirtualDevice(Device);
}

static NTSTATUS
GhostFidoHandleWriteInputReport(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
                                _In_ size_t InputBufferLength,
                                _In_ size_t OutputBufferLength)
{
    NTSTATUS status;
    WDFREQUEST pendingRequest;
    PUCHAR transferBuffer;
    ULONG transferBufferLength;
    GHOST_FIDO_UDE_INPUT_REPORT_REQUEST *reportRequest;

    if (InputBufferLength != sizeof(*reportRequest) || OutputBufferLength != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*reportRequest),
                                          (PVOID *)&reportRequest, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoValidateRequestHeader(reportRequest->Size,
                                            reportRequest->ProtocolMajor,
                                            reportRequest->ProtocolMinor,
                                            InputBufferLength,
                                            sizeof(*reportRequest));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (reportRequest->ReportSize != GHOST_FIDO_UDE_REPORT_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (reportRequest->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = WdfIoQueueRetrieveNextRequest(
        GhostFidoGetDeviceContext(Device)->InputPendingQueue, &pendingRequest);
    if (status == STATUS_NO_MORE_ENTRIES) {
        return GhostFidoPushReport(Device, TRUE, reportRequest->Report)
                   ? STATUS_SUCCESS
                   : STATUS_INSUFFICIENT_RESOURCES;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = UdecxUrbRetrieveBuffer(pendingRequest, &transferBuffer,
                                    &transferBufferLength);
    if (!NT_SUCCESS(status)) {
        GhostFidoDeferUrbCompletion(Device, pendingRequest, status, 0);
        (VOID)GhostFidoPushReport(Device, TRUE, reportRequest->Report);
        return STATUS_SUCCESS;
    }
    if (transferBufferLength != GHOST_FIDO_UDE_REPORT_SIZE) {
        GhostFidoDeferUrbCompletion(Device, pendingRequest,
                                    STATUS_INVALID_BUFFER_SIZE, 0);
        (VOID)GhostFidoPushReport(Device, TRUE, reportRequest->Report);
        return STATUS_SUCCESS;
    }

    RtlCopyMemory(transferBuffer, reportRequest->Report,
                  GHOST_FIDO_UDE_REPORT_SIZE);
    GhostFidoDeferUrbCompletion(Device, pendingRequest, STATUS_SUCCESS,
                                GHOST_FIDO_UDE_REPORT_SIZE);
    return STATUS_SUCCESS;
}

static NTSTATUS
GhostFidoHandleReadOutputReport(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
                                _In_ size_t InputBufferLength,
                                _In_ size_t OutputBufferLength)
{
    NTSTATUS status;
    GHOST_FIDO_UDE_OUTPUT_REPORT_REQUEST *reportRequest;
    GHOST_FIDO_UDE_OUTPUT_REPORT_RESPONSE *reportResponse;

    if (InputBufferLength != sizeof(*reportRequest) ||
        OutputBufferLength != sizeof(*reportResponse)) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*reportRequest),
                                          (PVOID *)&reportRequest, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GhostFidoValidateRequestHeader(reportRequest->Size,
                                            reportRequest->ProtocolMajor,
                                            reportRequest->ProtocolMinor,
                                            InputBufferLength,
                                            sizeof(*reportRequest));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (reportRequest->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*reportResponse),
                                           (PVOID *)&reportResponse, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!GhostFidoPopReport(Device, FALSE, reportResponse->Report)) {
        return STATUS_NO_MORE_ENTRIES;
    }

    reportResponse->Size = (ULONG)sizeof(*reportResponse);
    reportResponse->ProtocolMajor = GHOST_FIDO_UDE_PROTOCOL_MAJOR;
    reportResponse->ProtocolMinor = GHOST_FIDO_UDE_PROTOCOL_MINOR;
    reportResponse->ReportSize = GHOST_FIDO_UDE_REPORT_SIZE;
    reportResponse->Reserved = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS
GhostFidoHandleControlUrb(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request)
{
    NTSTATUS status;
    WDF_USB_CONTROL_SETUP_PACKET setupPacket;
    PUCHAR transferBuffer;
    ULONG transferBufferLength;
    ULONG bytesCompleted;
    USHORT descriptorType;
    USHORT descriptorIndex;

    status = UdecxUrbRetrieveControlSetupPacket(Request, &setupPacket);
    if (!NT_SUCCESS(status)) {
        GhostFidoDeferUrbCompletion(Device, Request, status, 0);
        return status;
    }
    transferBuffer = NULL;
    transferBufferLength = 0;
    status = UdecxUrbRetrieveBuffer(Request, &transferBuffer,
                                    &transferBufferLength);
    if (!NT_SUCCESS(status) && setupPacket.Packet.wLength != 0) {
        GhostFidoDeferUrbCompletion(Device, Request, status, 0);
        return status;
    }
    bytesCompleted = 0;
    descriptorType = (USHORT)(setupPacket.Packet.wValue.Value >> 8);
    descriptorIndex = (USHORT)(setupPacket.Packet.wValue.Value & 0xff);

    if (setupPacket.Packet.bm.Byte == 0x81 &&
        setupPacket.Packet.bRequest == USB_REQUEST_GET_DESCRIPTOR &&
        descriptorType == 0x22 && descriptorIndex == 0 &&
        setupPacket.Packet.wIndex.Value == 0) {
        bytesCompleted = min((ULONG)setupPacket.Packet.wLength,
                             transferBufferLength);
        bytesCompleted = min(bytesCompleted,
                             (ULONG)sizeof(GhostFidoReportDescriptor));
        if (bytesCompleted != 0) {
            RtlCopyMemory(transferBuffer, GhostFidoReportDescriptor,
                          bytesCompleted);
        }
        status = STATUS_SUCCESS;
    } else if (setupPacket.Packet.bm.Byte == 0x21 &&
               setupPacket.Packet.bRequest == 0x0a &&
               setupPacket.Packet.wIndex.Value == 0 &&
               setupPacket.Packet.wLength == 0) {
        // SET_IDLE is a no-op for the fixed-rate FIDO report profile.
        status = STATUS_SUCCESS;
    } else if (setupPacket.Packet.bm.Byte == 0xa1 &&
               setupPacket.Packet.bRequest == 0x02 &&
               setupPacket.Packet.wIndex.Value == 0 &&
               setupPacket.Packet.wLength >= 1 &&
               transferBufferLength >= 1) {
        transferBuffer[0] = 0;
        bytesCompleted = 1;
        status = STATUS_SUCCESS;
    } else if (setupPacket.Packet.bm.Byte == 0x21 &&
               setupPacket.Packet.bRequest == 0x0b &&
               setupPacket.Packet.wIndex.Value == 0 &&
               setupPacket.Packet.wLength == 0 &&
               setupPacket.Packet.wValue.Value <= 1) {
        status = STATUS_SUCCESS;
    } else if (setupPacket.Packet.bm.Byte == 0xa1 &&
               setupPacket.Packet.bRequest == 0x03 &&
               setupPacket.Packet.wIndex.Value == 0 &&
               setupPacket.Packet.wLength >= 1 &&
               transferBufferLength >= 1) {
        transferBuffer[0] = 1;
        bytesCompleted = 1;
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_NOT_SUPPORTED;
    }

    GhostFidoDeferUrbCompletion(Device, Request, status, bytesCompleted);
    return status;
}

VOID
GhostFidoEndpointIoctlCanceled(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request)
{
    GhostFidoDeferUrbCompletion(WdfIoQueueGetDevice(Queue), Request,
                                STATUS_CANCELLED, 0);
}

VOID
GhostFidoInputQueueCanceled(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request)
{
    GhostFidoDeferUrbCompletion(WdfIoQueueGetDevice(Queue), Request,
                                STATUS_CANCELLED, 0);
}

VOID
GhostFidoEndpointIoctl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                       _In_ size_t OutputBufferLength,
                       _In_ size_t InputBufferLength,
                       _In_ ULONG IoControlCode)
{
    NTSTATUS status;
    WDFDEVICE device;
    PGHOST_FIDO_ENDPOINT_QUEUE_CONTEXT queueContext;
    PGHOST_FIDO_DEVICE_CONTEXT deviceContext;
    PGHOST_FIDO_URB_REQUEST_CONTEXT requestContext;
    PUCHAR transferBuffer;
    ULONG transferBufferLength;
    UCHAR inputReport[GHOST_FIDO_REPORT_SIZE];

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    device = WdfIoQueueGetDevice(Queue);
    queueContext = GhostFidoGetEndpointQueueContext(Queue);
    deviceContext = GhostFidoGetDeviceContext(device);
    if (IoControlCode != IOCTL_INTERNAL_USB_SUBMIT_URB) {
        GhostFidoDeferUrbCompletion(device, Request,
                                    STATUS_INVALID_DEVICE_REQUEST, 0);
        return;
    }

    if (queueContext->EndpointAddress == GHOST_FIDO_ENDPOINT_CONTROL) {
        (VOID)GhostFidoHandleControlUrb(device, Request);
        return;
    }

    status = UdecxUrbRetrieveBuffer(Request, &transferBuffer,
                                    &transferBufferLength);
    if (!NT_SUCCESS(status)) {
        GhostFidoDeferUrbCompletion(device, Request, status, 0);
        return;
    }
    if (transferBufferLength != GHOST_FIDO_UDE_REPORT_SIZE) {
        GhostFidoDeferUrbCompletion(device, Request,
                                    STATUS_INVALID_BUFFER_SIZE, 0);
        return;
    }

    if (queueContext->EndpointAddress == GHOST_FIDO_ENDPOINT_INPUT) {
        if (GhostFidoPopReport(device, TRUE, inputReport)) {
            RtlCopyMemory(transferBuffer, inputReport, sizeof(inputReport));
            GhostFidoDeferUrbCompletion(device, Request, STATUS_SUCCESS,
                                        GHOST_FIDO_UDE_REPORT_SIZE);
            return;
        }
        status = GhostFidoGetOrCreateUrbContext(Request, &requestContext);
        if (!NT_SUCCESS(status)) {
            GhostFidoDeferUrbCompletion(device, Request, status, 0);
            return;
        }
        status = WdfRequestForwardToIoQueue(Request,
                                            deviceContext->InputPendingQueue);
        if (!NT_SUCCESS(status)) {
            GhostFidoDeferUrbCompletion(device, Request, status, 0);
        }
        return;
    }

    if (queueContext->EndpointAddress == GHOST_FIDO_ENDPOINT_OUTPUT) {
        if (!GhostFidoPushReport(device, FALSE, transferBuffer)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            status = STATUS_SUCCESS;
        }
        GhostFidoDeferUrbCompletion(device, Request, status,
                                    NT_SUCCESS(status)
                                        ? GHOST_FIDO_UDE_REPORT_SIZE
                                        : 0);
        return;
    }

    GhostFidoDeferUrbCompletion(device, Request, STATUS_NOT_SUPPORTED, 0);
}

VOID
GhostFidoEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                            _In_ size_t OutputBufferLength,
                            _In_ size_t InputBufferLength,
                            _In_ ULONG IoControlCode)
{
    NTSTATUS status;
    WDFDEVICE device;
    GHOST_FIDO_UDE_STATUS_REQUEST *statusRequest;
    GHOST_FIDO_UDE_STATUS_RESPONSE *statusResponse;

    device = WdfIoQueueGetDevice(Queue);
    if (UdecxWdfDeviceTryHandleUserIoctl(device, Request)) {
        return;
    }

    if (IoControlCode == IOCTL_GHOST_FIDO_UDE_ATTACH) {
        status = GhostFidoHandleAttach(device, Request, InputBufferLength,
                                       OutputBufferLength);
        WdfRequestComplete(Request, status);
        return;
    }
    if (IoControlCode == IOCTL_GHOST_FIDO_UDE_DETACH) {
        status = GhostFidoHandleDetach(device, Request, InputBufferLength,
                                       OutputBufferLength);
        WdfRequestComplete(Request, status);
        return;
    }
    if (IoControlCode == IOCTL_GHOST_FIDO_UDE_WRITE_INPUT_REPORT) {
        status = GhostFidoHandleWriteInputReport(
            device, Request, InputBufferLength, OutputBufferLength);
        WdfRequestComplete(Request, status);
        return;
    }
    if (IoControlCode == IOCTL_GHOST_FIDO_UDE_READ_OUTPUT_REPORT) {
        status = GhostFidoHandleReadOutputReport(
            device, Request, InputBufferLength, OutputBufferLength);
        if (NT_SUCCESS(status)) {
            WdfRequestCompleteWithInformation(
                Request, status, sizeof(GHOST_FIDO_UDE_OUTPUT_REPORT_RESPONSE));
        } else {
            WdfRequestComplete(Request, status);
        }
        return;
    }

    if (IoControlCode != IOCTL_GHOST_FIDO_UDE_QUERY_STATUS) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
    if (InputBufferLength < sizeof(*statusRequest) ||
        OutputBufferLength < sizeof(*statusResponse)) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }
    if (InputBufferLength != sizeof(*statusRequest)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*statusRequest),
                                          (PVOID *)&statusRequest, NULL);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    if (statusRequest->Size != (ULONG)sizeof(*statusRequest) ||
        statusRequest->Reserved != 0) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }
    if (statusRequest->ProtocolMajor != GHOST_FIDO_UDE_PROTOCOL_MAJOR ||
        statusRequest->ProtocolMinor > GHOST_FIDO_UDE_PROTOCOL_MINOR) {
        WdfRequestComplete(Request, STATUS_REVISION_MISMATCH);
        return;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*statusResponse),
                                            (PVOID *)&statusResponse, NULL);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    RtlZeroMemory(statusResponse, sizeof(*statusResponse));
    statusResponse->Size = (ULONG)sizeof(*statusResponse);
    statusResponse->Signature = GHOST_FIDO_UDE_STATUS_SIGNATURE;
    statusResponse->ProtocolMajor = GHOST_FIDO_UDE_PROTOCOL_MAJOR;
    statusResponse->ProtocolMinor = GHOST_FIDO_UDE_PROTOCOL_MINOR;
    statusResponse->Capabilities = GHOST_FIDO_UDE_CAP_CONTROLLER_READY;
    statusResponse->InputReportSize = GHOST_FIDO_REPORT_SIZE;
    statusResponse->OutputReportSize = GHOST_FIDO_REPORT_SIZE;

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS,
                                      sizeof(*statusResponse));
}

NTSTATUS
GhostFidoDeviceD0Entry(_In_ WDFDEVICE Device, _In_ UDECXUSBDEVICE UsbDevice)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(UsbDevice);
    return STATUS_SUCCESS;
}

NTSTATUS
GhostFidoDeviceD0Exit(_In_ WDFDEVICE Device, _In_ UDECXUSBDEVICE UsbDevice,
                      _In_ UDECX_USB_DEVICE_WAKE_SETTING WakeSetting)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(WakeSetting);
    return STATUS_SUCCESS;
}

VOID
GhostFidoResetEndpoint(_In_ UDECXUSBENDPOINT Endpoint, _In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Endpoint);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}
