// Windows UDE/KMDF scaffold. Build only with the Windows Driver Kit.
// The TODOs are deliberate release gates; this file must not be packaged as a
// working driver until the callbacks and signing/install path are complete.

#include <ntddk.h>
#include <wdf.h>
#include <Udecx.h>

#define GHOST_FIDO_VENDOR_ID 0x0000
#define GHOST_FIDO_PRODUCT_ID 0x0000
#define GHOST_FIDO_REPORT_SIZE 64

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD GhostFidoEvtDeviceAdd;
EVT_UDECX_WDF_DEVICE_QUERY_USB_CAPABILITY GhostFidoQueryUsbCapability;
EVT_UDECX_WDF_DEVICE_RESET GhostFidoResetController;
EVT_UDECX_USB_DEVICE_DEFAULT_ENDPOINT_ADD GhostFidoAddDefaultEndpoint;
EVT_UDECX_USB_DEVICE_ENDPOINT_ADD GhostFidoAddEndpoint;
EVT_UDECX_USB_DEVICE_ENDPOINTS_CONFIGURE GhostFidoConfigureEndpoints;
EVT_UDECX_USB_DEVICE_D0_ENTRY GhostFidoDeviceD0Entry;
EVT_UDECX_USB_DEVICE_D0_EXIT GhostFidoDeviceD0Exit;
EVT_UDECX_USB_ENDPOINT_RESET GhostFidoResetEndpoint;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL GhostFidoEndpointIoctl;

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
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(DeviceInit);

    // TODO: call UdecxInitializeWdfDeviceInit, create the controller device,
    // register GhostFidoQueryUsbCapability/GhostFidoResetController, create
    // the virtual device, descriptors, endpoint queues, and control IOCTL.
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoQueryUsbCapability(_In_ WDFDEVICE Device,
                                     _In_ PGUID CapabilityType,
                                     _Out_ PBOOLEAN Supported)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(CapabilityType);
    *Supported = FALSE;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoResetController(_In_ WDFDEVICE Device)
{
    UNREFERENCED_PARAMETER(Device);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoAddDefaultEndpoint(_In_ UDECXUSBDEVICE UsbDevice,
                                      _In_ PUDECXUSBENDPOINT_INIT EndpointInit)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(EndpointInit);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoAddEndpoint(_In_ UDECXUSBDEVICE UsbDevice,
                               _In_ PUDECXUSBENDPOINT_INIT EndpointInit)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(EndpointInit);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoConfigureEndpoints(_In_ UDECXUSBDEVICE UsbDevice,
                                      _In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoDeviceD0Entry(_In_ UDECXUSBDEVICE UsbDevice)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoDeviceD0Exit(_In_ UDECXUSBDEVICE UsbDevice)
{
    UNREFERENCED_PARAMETER(UsbDevice);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GhostFidoResetEndpoint(_In_ UDECXUSBENDPOINT Endpoint)
{
    UNREFERENCED_PARAMETER(Endpoint);
    return STATUS_NOT_IMPLEMENTED;
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
