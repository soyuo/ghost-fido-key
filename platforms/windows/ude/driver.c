// Windows UDE/KMDF scaffold. Build only with the Windows Driver Kit.
// The TODOs are deliberate release gates; this file must not be packaged as a
// working driver until the callbacks and signing/install path are complete.

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <wdfusb.h>
#include <Udecx.h>
#include "ghost_fido_ude_protocol.h"

#define GHOST_FIDO_VENDOR_ID 0x0000
#define GHOST_FIDO_PRODUCT_ID 0x0000
#define GHOST_FIDO_REPORT_SIZE 64

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD GhostFidoEvtDeviceAdd;
EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY GhostFidoQueryUsbCapability;
EVT_UDECX_USB_DEVICE_DEFAULT_ENDPOINT_ADD GhostFidoAddDefaultEndpoint;
EVT_UDECX_USB_DEVICE_ENDPOINT_ADD GhostFidoAddEndpoint;
EVT_UDECX_USB_DEVICE_ENDPOINTS_CONFIGURE GhostFidoConfigureEndpoints;
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

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
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
    status = WdfIoQueueCreate(device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Device enumeration and endpoint I/O are added in later implementation steps.
    return STATUS_SUCCESS;
}

NTSTATUS GhostFidoQueryUsbCapability(_In_ WDFDEVICE Device,
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

VOID GhostFidoEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
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

NTSTATUS GhostFidoAddDefaultEndpoint(_In_ UDECXUSBDEVICE UsbDevice,
                                      _In_ PUDECXUSBENDPOINT_INIT EndpointInit)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(EndpointInit);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoAddEndpoint(_In_ UDECXUSBDEVICE UsbDevice,
                               _In_ PUDECX_USB_ENDPOINT_INIT_AND_METADATA EndpointToCreate)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(EndpointToCreate);
    return STATUS_NOT_IMPLEMENTED;
}

VOID GhostFidoConfigureEndpoints(_In_ UDECXUSBDEVICE UsbDevice,
                                  _In_ WDFREQUEST Request,
                                  _In_ PUDECX_ENDPOINTS_CONFIGURE_PARAMS Params)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(Params);
}

NTSTATUS GhostFidoDeviceD0Entry(_In_ WDFDEVICE Device,
                             _In_ UDECXUSBDEVICE UsbDevice)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(UsbDevice);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoDeviceD0Exit(_In_ WDFDEVICE Device,
                            _In_ UDECXUSBDEVICE UsbDevice,
                            _In_ UDECX_USB_DEVICE_WAKE_SETTING WakeSetting)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(WakeSetting);
    return STATUS_NOT_IMPLEMENTED;
}

VOID GhostFidoResetEndpoint(_In_ UDECXUSBENDPOINT Endpoint,
                            _In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Endpoint);
    UNREFERENCED_PARAMETER(Request);
}

VOID GhostFidoEndpointIoctl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                            _In_ size_t OutputBufferLength,
                            _In_ size_t InputBufferLength,
                            _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(IoControlCode);
    WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
}
