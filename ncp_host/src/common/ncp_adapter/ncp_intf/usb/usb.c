/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <stdbool.h>

#include "ncp_adapter.h"
#include "usb.h"

/*******************************************************************************
 * Defines
 ******************************************************************************/

#define USB_TIMEOUT	        10        /* Timeout value (in ms) */

/*******************************************************************************
 * Variables
 ******************************************************************************/
char req_manufact_id[] = "NXP SEMICONDUCTORS";
static pthread_t       usb_event_thread;
static pthread_mutex_t usb_event_thread_mutex;
sem_t usb_lpm_sem;

libusb_hotplug_callback_handle usb_cb_Handle = 0;
static bool usb_hotplug_init = false;

/*******************************************************************************
 * Public functions
 ******************************************************************************/
static void* usb_handle_event(void *argv)
{
    usb_device_t *dev = (usb_device_t *)argv;

    while(pthread_mutex_trylock(&usb_event_thread_mutex) != 0) 
	{
		libusb_handle_events(dev->context);
    }
    pthread_exit(NULL);
}

static void* usb_handle_lpm(void *argv)
{
    while (1)
    {
        sem_wait(&usb_lpm_sem);
        ncp_adap_d("ncp_usb_deinit \r\n");
        ncp_usb_deinit();
        ncp_usb_init();
        ncp_adap_d("ncp_usb_init \r\n");
    }

    pthread_exit(NULL);
}

static int usb_hotplugCB(libusb_context *libusbCtx, libusb_device *dev, libusb_hotplug_event event, void *userData)
{
    if(event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED)
    {
        ncp_adap_d("LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED\r\n");
        sem_post(&usb_lpm_sem);
    }
    else if(event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT)
    {
        ncp_adap_d("LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT\r\n");
    }
    return 0;
}

int usb_lpm_init()
{
    pthread_t usb_lpm_thread;

    if(true == usb_hotplug_init)
        return NCP_STATUS_SUCCESS;
    
    if (sem_init(&usb_lpm_sem, 0, 1) == -1)
    {
        ncp_adap_e("Failed to init usb_lpm_sem!\r\n");
        return NCP_STATUS_ERROR;
    }
    sem_wait(&usb_lpm_sem);

    usb_lpm_thread = pthread_create(&usb_lpm_thread, NULL,(void *)usb_handle_lpm, NULL);
    if (usb_lpm_thread != 0)
    {
        sem_destroy(&usb_lpm_sem);
        ncp_adap_e("Failed to creat usb_lpm_thread \n");

        return NCP_STATUS_ERROR;
    }

    usb_hotplug_init = true;
    
    return NCP_STATUS_SUCCESS;
}

/*
 * Init USB instance.
 */
ncp_status_t usb_init(usb_device_t *dev)
{
    int ret = NCP_STATUS_SUCCESS;
    libusb_hotplug_event monitor_event = LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT;
    libusb_hotplug_flag flag = LIBUSB_HOTPLUG_NO_FLAGS ;
    int class = LIBUSB_HOTPLUG_MATCH_ANY;
    dev->context = NULL;

    libusb_init(&(dev->context));

    if (config_usb(dev) == NCP_STATUS_ERROR )
    {
        ncp_adap_e("USB: Could not configure usb device properly \n");

        return NCP_STATUS_ERROR;
    }

    /* Open Device with VendorID and ProductID  */
	dev->handle = libusb_open_device_with_vid_pid(dev->context, dev->vendorid, dev->productid);

	if (!dev->handle)
    {
        ncp_adap_e("Unable to open USB device with request parameters \n");

		return NCP_STATUS_ERROR;
	}
    
    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) 
    {
        ncp_adap_e("Don't support hotplug feature");
        return NCP_STATUS_ERROR;
    }
    
    ret = libusb_hotplug_register_callback(dev->context, monitor_event, flag, dev->vendorid, dev->productid, class, usb_hotplugCB, NULL, &usb_cb_Handle);
    
    if(ret)
    {
        ncp_adap_e("libusb_hotplug_register_callback falied\n");
        return NCP_STATUS_ERROR;
    }

    pthread_mutex_init(&usb_event_thread_mutex, NULL);
    pthread_mutex_lock(&usb_event_thread_mutex);    
    ret = pthread_create(&usb_event_thread, NULL, (void *)usb_handle_event, dev);
    if (ret != 0)
    {
        ncp_adap_e("ERROR usb_event_thread creat \n");
        pthread_mutex_unlock(&usb_event_thread_mutex);
        pthread_mutex_destroy(&usb_event_thread_mutex);
        libusb_hotplug_deregister_callback(dev->context, usb_cb_Handle);
        
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Receive USB data.
 */

ncp_status_t usb_receive(usb_device_t *dev, int8_t *buf, uint32_t len, size_t *nb_bytes)
{

    size_t bytesread;
    int8_t ret;

	ret = libusb_bulk_transfer(dev->handle, dev->usb_endpoint_in, buf, len, &bytesread, USB_TIMEOUT);

    if (ret == 0 || (ret == LIBUSB_ERROR_TIMEOUT && bytesread))
    {
        /* 'bytesread' number of bytes received in 'buf' */
        *nb_bytes = bytesread;        
    }
    else
    {
        //ncp_adap_e("USB: Error while reading \n");
        
        return NCP_STATUS_ERROR;
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Send USB data.
 */

ncp_status_t usb_send(usb_device_t *dev, int8_t *buf, uint32_t len)
{
    uint32_t actual_sent_bytes;
    int8_t ret;

    /* Request bulk transfer via usb */
    ret = libusb_bulk_transfer(dev->handle, dev->usb_endpoint_out, buf, len, &actual_sent_bytes, USB_TIMEOUT);

    if (ret == 0)
    {

        if(len != actual_sent_bytes)
        {
            printf("Need to develop condition to keep track to send all bytes \n");
        }
    }

    return NCP_STATUS_SUCCESS;
}

/*
 * Deinit USB instance.
 */
void usb_deinit(usb_device_t *dev)
{
    libusb_hotplug_deregister_callback(dev->context, usb_cb_Handle);
    pthread_mutex_unlock(&usb_event_thread_mutex);
    pthread_join(usb_event_thread, NULL);
    
	if (dev->handle)
    {
        libusb_release_interface (dev->handle, 0);
        libusb_close(dev->handle);
	}
}

ncp_status_t config_usb(usb_device_t *usb_dev)
{
    struct libusb_device **usb_devices;
    struct libusb_device_handle *usb_handle = NULL;
    struct libusb_device *dev;
    struct libusb_device_descriptor device_desc;

    int8_t ret = 1, get_result = 0, rot = 0, found_dev = 0;
    int8_t count_devs;
    char get_manufact_id[64], get_productt_id[64];

    // Get all attached USB devices
    count_devs = libusb_get_device_list(NULL, &usb_devices);
    if (count_devs < 0)
    {
        ncp_adap_e("No usb found on the system\n");

        return NCP_STATUS_ERROR;
    }

    while ((dev = usb_devices[rot++]) != NULL)
    {
        ret = libusb_get_device_descriptor(dev, &device_desc);
        if (ret < 0)
        {
            ncp_adap_e("Failed to get device descriptor\n");
            libusb_free_device_list(usb_devices, 1);
            libusb_close(usb_handle);

            return NCP_STATUS_ERROR;
        }

        get_result = libusb_open(dev, &usb_handle);
        if (get_result < 0)
        {
            ncp_adap_e("Error opening USB device\n");
            libusb_free_device_list(usb_devices, 1);
            libusb_close(usb_handle);

            return NCP_STATUS_ERROR;
        }

        get_result = libusb_get_string_descriptor_ascii(usb_handle, device_desc.iManufacturer, (unsigned char*) get_manufact_id, sizeof(get_manufact_id));
        if (get_result < 0)
        {
            libusb_free_device_list(usb_devices, 1);
            libusb_close(usb_handle);

            return NCP_STATUS_ERROR;
        }

        get_result = libusb_get_string_descriptor_ascii(usb_handle, device_desc.iProduct, (unsigned char*) get_productt_id, sizeof(get_productt_id));
        if (get_result < 0)
        {
            libusb_free_device_list(usb_devices, 1);
            libusb_close(usb_handle);

            return NCP_STATUS_ERROR;
        }

        if (strcmp(get_manufact_id,req_manufact_id) == 0)
        {
            found_dev = 1;
            break;
        }

    }

    if(found_dev == 0)
    {
        ncp_adap_e("Requested USB device not found\n");
        libusb_free_device_list(usb_devices, 1);
        libusb_close(usb_handle);

        return NCP_STATUS_ERROR;
    }


    libusb_free_device_list(usb_devices, 1);

    if(libusb_kernel_driver_active(usb_handle, 0) == 1)
    {
        if(libusb_detach_kernel_driver(usb_handle, 0) == 0)
            ncp_adap_e("USB: Kernel Driver Detached\n");
        else
        {
            ncp_adap_e("USB: could not detach kernel driver\n");
            libusb_free_device_list(usb_devices, 1);
            libusb_close(usb_handle);

            return NCP_STATUS_ERROR;
        }
    }

    get_result = libusb_claim_interface(usb_handle, 0);
    if(get_result < 0)
    {
        ncp_adap_e("USB: couldn't claim USB requested interface\n");
        libusb_free_device_list(usb_devices, 1);
        libusb_close(usb_handle);

        return NCP_STATUS_ERROR;
    }

    set_IntfEndpoints(dev, usb_dev);

    return NCP_STATUS_SUCCESS;
}

void set_IntfEndpoints(struct libusb_device *req_device, usb_device_t *usb_dev)
{
    struct libusb_config_descriptor *dconfig;
    struct libusb_endpoint_descriptor *endpoint;
    struct libusb_device_descriptor selected_dev_desc;
    int8_t endpoint_index, interface_index = 0, altsetting_index, ret_descr = 1;

    libusb_get_active_config_descriptor(req_device, &dconfig);

    for (interface_index = 0; interface_index<dconfig->bNumInterfaces; interface_index++)
    {
        const struct libusb_interface *iface = &dconfig->interface[interface_index];
        for (altsetting_index = 0; altsetting_index<iface->num_altsetting; altsetting_index++)
        {
            const struct libusb_interface_descriptor *altsetting = &iface->altsetting[altsetting_index];

            for(endpoint_index=0; endpoint_index<altsetting->bNumEndpoints; endpoint_index++)
            {
                endpoint = &altsetting->endpoint[endpoint_index];

                if(endpoint->bmAttributes == 2) /* Select device with bulk transfer attribute */
                {
                    ret_descr = libusb_get_device_descriptor(req_device, &selected_dev_desc);

                    usb_dev->productid = selected_dev_desc.idProduct;
                    usb_dev->vendorid = selected_dev_desc.idVendor;

                    if (ret_descr < 0)
                    {
                        libusb_free_device_list(req_device, 1);
                        libusb_close(req_device);
                    }

                    /*Last bit decides if its direction is in or out*/
                    if( (endpoint->bEndpointAddress) >> 7 == 1 )
                    {
                        usb_dev->usb_endpoint_in = endpoint->bEndpointAddress;
                    }
                    else
                    {
                        usb_dev->usb_endpoint_out = endpoint->bEndpointAddress;

                    }

                }

            }
        }
    }

    libusb_free_config_descriptor(NULL);
}

