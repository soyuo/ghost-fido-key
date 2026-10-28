// Windows UDE/KMDF scaffold. Build only with the Windows Driver Kit.
// Virtual-device traffic remains unsupported until a later implementation step.

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
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

typedef struct _GHOST_FIDO_DEVICE_CONTEXT {
    PUDECXUSBDEVICE_INIT DeviceInit;
    UDECXUSBDEVICE UsbDevice;
    UDECXUSBENDPOINT ControlEndpoint;
    UDECXUSBENDPOINT InputEndpoint;
    UDECXUSBENDPOINT OutputEndpoint;
} GHOST_FIDO_DEVICE_CONTEXT, *PGHOST_FIDO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GHOST_FIDO_DEVICE_CONTEXT,
                                   GhostFidoGetDeviceContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD GhostFidoEvtDeviceAdd;
EVT_WDF_DEVICE_CONTEXT_CLEANUP GhostFidoEvtDeviceContextCleanup;
EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY GhostFidoQueryUsbCapability;
EVT_UDECX_USB_DEVICE_D0_ENTRY GhostFidoDeviceD0Entry;
EVT_UDECX_USB_DEVICE_D0_EXIT GhostFidoDeviceD0Exit;
EVT_UDECX_USB_ENDPOINT_RESET GhostFidoResetEndpoint;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL GhostFidoEndpointIoctl;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL GhostFidoEvtIoDeviceControl;

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

static BOOLEAN
GhostFidoHasConfiguredIdentity(VOID)
{
    return (GHOST_FIDO_VENDOR_ID != 0 &&
            GHOST_FIDO_VENDOR_ID < 0xffff &&
            GHOST_FIDO_PRODUCT_ID != 0 &&
            GHOST_FIDO_PRODUCT_ID <= 0xffff);
}

static NTSTATUS
GhostFidoCreateEndpoint(_In_ WDFDEVICE Device,
                        _In_ UDECXUSBDEVICE UsbDevice,
                        _In_ UCHAR EndpointAddress,
                        _Out_ UDECXUSBENDPOINT *Endpoint)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    PUDECXUSBENDPOINT_INIT endpointInit;
    UDECX_USB_ENDPOINT_CALLBACKS callbacks;

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
    status = WdfIoQueueCreate(Device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

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
    if (!GhostFidoHasConfiguredIdentity()) {
        // A build without explicitly assigned VID/PID keeps the controller only.
        return STATUS_SUCCESS;
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

    UDECX_USB_DEVICE_PLUG_IN_OPTIONS_INIT(&plugInOptions);
    status = UdecxUsbDevicePlugIn(context->UsbDevice, &plugInOptions);
    return status;
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
                         L"D:P(A;;GR;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)");
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
    status = WdfIoQueueCreate(device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return GhostFidoCreateAndPlugInVirtualDevice(device);
}

VOID
GhostFidoEvtDeviceContextCleanup(_In_ WDFOBJECT Object)
{
    WDFDEVICE device;
    PGHOST_FIDO_DEVICE_CONTEXT context;

    device = (WDFDEVICE)Object;
    context = GhostFidoGetDeviceContext(device);

    if (context->UsbDevice != WDF_NO_HANDLE) {
        // UDE requires PASSIVE_LEVEL for orderly plug-out and deletion.
        (VOID)UdecxUsbDevicePlugOutAndDelete(context->UsbDevice);
        context->UsbDevice = WDF_NO_HANDLE;
    }
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

VOID
GhostFidoEndpointIoctl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                       _In_ size_t OutputBufferLength,
                       _In_ size_t InputBufferLength,
                       _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(IoControlCode);
    WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
}
