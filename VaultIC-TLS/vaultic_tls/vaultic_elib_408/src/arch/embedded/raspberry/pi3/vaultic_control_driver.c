/**
 * @file
 *
 * @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
 *
 * @note    <b>DISCLAIMER</b>
 *
 * @note    Copyright (C) 2020 Wisekey
 *
 * @note    All products are provided by Wisekey subject to Wisekey Evaluation License Terms and Conditions
 * @note    and the provisions of any agreements made between Wisekey and the Customer concerning the same
 * @note    subject matter.
 * @note    In ordering a product covered by this document the Customer agrees to be bound by those Wisekey's
 * @note    Evaluation License Terms and Conditions and agreements and nothing contained in this document
 * @note    constitutes or forms part of a contract (with the exception of the contents of this disclaimer notice).
 * @note    A copy of Wisekey's Evaluation License Terms and Conditions is available on request. Export of any
 * @note    Wisekey product outside of the EU may require an export license.
 *
 * @note    The information in this document is provided in connection with Wisekey products. No license,
 * @note    express or implied, by estoppel or otherwise, to any intellectual property right is granted by this
 * @note    document or in connection with the provisions of Wisekey products.
 *
 * @note    Wisekey makes no representations or warranties with respect to the accuracy or completeness of the
 * @note    contents of this document and reserves the right to make changes to specifications and product
 * @note    descriptions at any time without notice.
 *
 * @note    THE PRODUCT AND THE RELATED DOCUMENTATION ARE PROVIDED "AS IS", AND CUSTOMER UNDERSTANDS
 * @note    THAT IT ASSUMES ALL RISKS IN RELATION TO ITS USE OF THE PRODUCT AND THE PRODUCT'S
 * @note    QUALITY AND PERFORMANCE.
 *
 * @note    EXCEPT AS SET FORTH IN INSIDE SECURE'S EVALUATION LICENSE TERMS AND CONDITIONS OR IN ANY
 * @note    AGREEMENTS MADE BETWEEN WISEKEY AND THE CUSTOMER CONCERNING THE SAME SUBJECT MATTER,
 * @note    WISEKEY OR ITS SUPPLIERS OR LICENSORS ASSUME NO LIABILITY WHATSOEVER. CUSTOMER
 * @note    AGREES AND ACKNOWLEDGES THAT WISEKEY SHALL HAVE NO RESPONSIBILITIES TO CUSTOMER TO
 * @note    CORRECT ANY DEFECTS OR PROBLEMS IN THE PRODUCT OR THE RELATED DOCUMENTATION, OR TO
 * @note    ENSURE THAT THE PRODUCT OPERATES PROPERLY.  WISEKEY DISCLAIMS ANY AND ALL WARRANTIES
 * @note    WITH RESPECT TO THE PRODUCT AND THE RELATED DOCUMENTATION, WHETHER EXPRESS, STATUTORY
 * @note    OR IMPLIED INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTY OF MERCHANTABILITY,
 * @note    SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 *
 * @note    WISEKEY SHALL HAVE NO LIABILITY WHATSOEVER TO CUSTOMER IN CONNECTION WITH THIS
 * @note    WISEKEY'S EVALUATION TERMS AND CONDITIONS, INCLUDING WITHOUT LIMITATION, LIABILITY FOR
 * @note    ANY PROBLEMS IN OR CAUSED BY THE PRODUCT OR THE RELATED DOCUMENTATION, WHETHER DIRECT,
 * @note    INDIRECT, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, SPECIAL OR INCIDENTAL DAMAGES (INCLUDING,
 * @note    WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, LOSS OF REVENUE, BUSINESS INTERRUPTION,
 * @note    LOSS OF GOODWILL, OR LOSS OF INFORMATION OR DATA) NOOWITHSTANDING THE THEORY OF
 * @note    LIABILITY UNDER WHICH SAID DAMAGES ARE SOUGHT, INCLUDING BUT NOT LIMITED TO CONTRACT,
 * @note    TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY, STRICT LIABILITY, STATUTORY LIABILITY OR
 * @note    OTHERWISE, EVEN IF WISEKEY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 *
 *
 * @brief   VaultIC_API Control driver
 *
 * @details
 *
 */

#include "vaultic_config.h"

#if (defined (RST_CTRL_BY_GPIO) || defined (VCC_CTRL_BY_GPIO)) && ( VLT_PLATFORM == VLT_EMBEDDED)
#include "vaultic_typedefs.h"
#include "vaultic_timer_delay.h"
#include "vaultic_control_driver.h"

#include <linux/gpio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#ifdef RPI_PRINT_ERRORS
#include <stdio.h>
#define LOG_ERROR(...) printf(__VA_ARGS__)
#else
#define LOG_ERROR(...) do { } while(0);
#endif

#define DEV_NAME "/dev/gpiochip0"

#ifdef VCC_CTRL_BY_GPIO
/* Definition of VCC_CTRL Pin */
#define VCC_GPIO_NUM            25
static int vcc_line_handle=-1;
#endif //VCC_CTRL_BY_GPIO

#ifdef RST_CTRL_BY_GPIO
/* Definition of RST_CTRL Pin */
#define RST_GPIO_NUM            27
static int rst_line_handle=-1;
#endif //RST_CTRL_BY_GPIO

static int gpio_init(int line_offset)
{
    int fd, ret;

    fd = open(DEV_NAME, O_RDONLY);
    if (fd < 0)
    {
        LOG_ERROR("gpio_ctrl_init Unable to open %s: %s\n", DEV_NAME, strerror(errno));
        return -1;
    }

    /* Configure pins as output */
    struct gpiohandle_request rq={0};

    rq.lines = 1;
    rq.flags = GPIOHANDLE_REQUEST_OUTPUT;
    rq.lineoffsets[0] = line_offset;
    rq.default_values[0] = 1;

    switch(line_offset)
    {

#ifdef RST_CTRL_BY_GPIO
        case RST_GPIO_NUM:
            strcpy(rq.consumer_label, "VAULTIC_RST_CTRL");
        break;
#endif

#ifdef VCC_CTRL_BY_GPIO
        case VCC_GPIO_NUM:
            strcpy(rq.consumer_label, "VAULTIC_VCC_CTRL");
        break;
#endif

        default:
            LOG_ERROR("gpio_init Unexpected gpio line offset %d\n", line_offset);
            return -1;
    }

    ret = ioctl(fd, GPIO_GET_LINEHANDLE_IOCTL, &rq);
    close(fd);
    if (ret == -1)
    {
        LOG_ERROR("gpio_init Unable to get line handle from ioctl : %s\n", strerror(errno));
        return -1;
    }

    // return gpio line handle
    return rq.fd;
}

static void set_gpio(int gpio_handle, __u8 value )
{
    /* Configure gpio (if not already done) */
    if (gpio_handle == -1)
    {
        LOG_ERROR("set_gpio Invalid line handle\n");;
        return;
    }

    struct gpiohandle_data data={0};
    data.values[0] = value;

    int ret = ioctl(gpio_handle, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
    if (ret == -1)
    {
        LOG_ERROR("set_gpio Unable to set line value using ioctl : %s\n", strerror(errno));
    }
}

#ifdef VCC_CTRL_BY_GPIO
static void set_gpio_power(int value)
{
    /* Configure GPIO if not done yet */
    if(vcc_line_handle == -1)
    {
        vcc_line_handle = gpio_init(VCC_GPIO_NUM);
    }

    /* Set VCC_CTRL GPIO pin */
    set_gpio(vcc_line_handle, value);
}

void VltControlPowerOn(void)
{
    /* Power On by setting VCC_CTRL GPIO pin to 0 */
    set_gpio_power(0);
}

void VltControlPowerOff(void)
{
    /* Power On by setting VCC_CTRL GPIO pin to 1 */
    set_gpio_power(1);
}
#endif // VCC_CTRL_BY_GPIO

#ifdef RST_CTRL_BY_GPIO
static void set_gpio_reset(int value)
{
    /* Configure GPIO if not done yet */
    if(rst_line_handle == -1)
    {
        rst_line_handle = gpio_init(RST_GPIO_NUM);
    }

    /* Set RST_CTRL GPIO pin */
    set_gpio(rst_line_handle, value);
}

void VltControlResetLow(void)
{
    /* Set RST_CTRL GPIO pin to 0  */
    set_gpio_reset(0);
}

void VltControlResetHigh(void)
{
    /* Set RST_CTRL GPIO pin to 1  */
    set_gpio_reset(1);
}
#endif // RST_CTRL_BY_GPIO

void VltControlUninit(void)
{
#ifdef RST_CTRL_BY_GPIO
    close(rst_line_handle);
    rst_line_handle = -1;
#endif

#ifdef VCC_CTRL_BY_GPIO
    close(vcc_line_handle);
    vcc_line_handle = -1;
#endif
}


#endif // (defined (RST_CTRL_BY_GPIO) || defined (VCC_CTRL_BY_GPIO)) && ( VLT_PLATFORM == VLT_EMBEDDED)
