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
 * @brief   VaultIC_API TWI driver
 *
 * @details
 *
 */

#include "vaultic_config.h"
#if( VLT_ENABLE_TWI == VLT_ENABLE ) && ( VLT_PLATFORM == VLT_EMBEDDED)
#if( VLT_ENABLE_SPI == VLT_ENABLE )
#error "TWI and SPI drivers can not enabled together"
#endif

#include "vaultic_typedefs.h"
#include "vaultic_timer_delay.h"
#include "vaultic_twi_driver.h"
#include <stdlib.h>
#include <string.h>

#define RASPBERRY_PI2 02
#define RASPBERRY_PI3 03
#define RASPBERRY_PI4 04

#ifdef RPI_PRINT_ERRORS
#include <stdio.h>
#define LOG_ERROR(...) printf(__VA_ARGS__)
#else
#define LOG_ERROR(...) do { } while(0);
#endif

#ifdef TWI_TRACE_ERRORS
uint32_t twi_total_err_cnt_tx=0;
uint32_t twi_total_err_cnt_rx=0;
#endif

#define MAX_ERR_COUNT 3
#define I2C_RETRY_TIMING 10 /* in ms */

#define BCM_MAX_CORE_CLK_PI2 400000000
#define BCM_MAX_CORE_CLK_PI3 400000000
#define BCM_MAX_CORE_CLK_PI4 500000000

static int GetRpiModel(void);
static off_t GetI2CBaseAddress(void);
static uint32_t GetMaxCoreClock(void);

static int SetBitRate(uint16_t bitrate);
static void SetI2CAddress(uint8_t address);

uint8_t gu8I2cAddress;

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <sys/mman.h>
#define I2C_DEVICE "/dev/i2c-1"
static int fd = -1;

static off_t  i2c_base_addr;

#define I2C1_BASE_PI2 (0x3f804000)
#define I2C1_BASE_PI3 (0x3f804000)
#define I2C1_BASE_PI4 (0xfe804000)

typedef struct {
    uint32_t C;
    uint32_t S;
    uint32_t DLEN;
    uint32_t A;
    uint32_t FIFO;
    uint32_t DIV;
    uint32_t DEL;
    uint32_t CLKT;
}  i2c_reg_map_t;


/**
 * @brief   Initialize TWI driver
 *
 * @param   u8I2cAddress   I2C address
 * @param   u16BitRate     bit rate (in kbits)
 *
 */

uint16_t VltTwiDriverInit(uint8_t u8I2cAddress, uint16_t u16BitRate)
{
    // Get Address of I2C controller
    i2c_base_addr=GetI2CBaseAddress();

    if(i2c_base_addr==-1) {
        LOG_ERROR("VltTwiDriverInit Unable to get I2C base address\n");
        return TWI_FAIL;
    }

    // Open I2C bus
    fd = open(I2C_DEVICE, O_RDWR);
    if (fd == -1) {
        LOG_ERROR("VltTwiDriverInit Failed to open %s \n",I2C_DEVICE);
        return TWI_FAIL;
    }

#if (VAULT_IC_TARGET  ==   VAULTIC2XX)
    // Enforce bitrate to 50k to compensate clock stretch bug on raspberry
    // cf http://www.advamation.com/knowhow/raspberrypi/rpi-i2c-bug.html
    if(SetBitRate(50) != 0)
    {
        LOG_ERROR("unable to set bitrate (run app with sudo privilege) \n");
        return TWI_FAIL;
    }
#else
    SetBitRate(u16BitRate);
#endif

    // Set I2C address
    SetI2CAddress(u8I2cAddress);
    gu8I2cAddress = u8I2cAddress;


    return TWI_OK;
}

/**
 * @brief   Deinitialize TWI driver
 *
 */
void VltTwiDriverDeInit(void)
{
    
    if (fd !=-1 ) close(fd);
    fd = -1;
}


/**
 * @brief   Send bytes over the TWI interface
 *
 * @param   u8I2cAddress   I2C address
 * @param   pu8BytesToSend   buffer holding the data to send
 * @param   u16NumBytesToSend number of bytes to send
 * @param   u32BusTimeOut communication timeout in ms
 *
 * @return    TWI_OK or TWI_FAIL
 *
 */
uint16_t VltTwiDriverSendBytes(uint8_t u8I2cAddress, const uint8_t *pu8BytesToSend, uint16_t u16NumBytesToSend, uint32_t u32BusTimeOut)
{
    uint16_t err_cnt = 0;

    while (err_cnt++ < MAX_ERR_COUNT)
    {
        if (write(fd, pu8BytesToSend, u16NumBytesToSend) == u16NumBytesToSend)
            return TWI_OK;

        VltSleep(I2C_RETRY_TIMING*1000);

        LOG_ERROR("**I2C Transmit error #%d \n",err_cnt);

#ifdef TWI_TRACE_ERRORS
        twi_total_err_cnt_tx++;
#endif
    }

    return TWI_FAIL;
}

/**
 * @brief   Receives bytes from the device.
 *
 * \par Description:
 *   -# Receive the specified number of bytes in the given buffer. The end of reception is
 *        detected thanks to a timeout
 *   -# Take into account a potential mute line
 *
 * @param   u8I2cAddress               I2C address
 * @param   pu8Buffer                 buffer that will hold the data to receive
 * @param   u16NumBytesToReceive      number of bytes to receive
 * @param   u32BusTimeOut             bus communication timeout in milliseconds
 * @param   u32ResponseTimeOut        total response timeout in milliseconds
 *
 * @return TWI_OK or TWI_FAIL
 *
 */
uint16_t VltTwiDriverReceiveBytes(uint8_t u8I2cAddress, uint8_t * pu8Buffer, uint16_t u16NumBytesToReceive, uint32_t u32BusTimeOut, uint32_t u32ResponseTimeOut)
{
    // set I2C timeout
    if (ioctl(fd, I2C_TIMEOUT, u32ResponseTimeOut) < 0)
    {
        LOG_ERROR("VltTwiDriverReceiveBytes Failed to set timeout\n");
        return TWI_FAIL;
    }

    VltTimerStart(u32ResponseTimeOut);

    while(VltTimerIsExpired() == 0)    
    {
        int nbReceived = read(fd, pu8Buffer, u16NumBytesToReceive);
        if ( nbReceived == u16NumBytesToReceive)
            return TWI_OK;

        VltSleep(I2C_RETRY_TIMING); 
    }

    VltTimerStop();

    // Timeout
    LOG_ERROR("**I2C Receive timeout \n");
#ifdef TWI_TRACE_ERRORS
    twi_total_err_cnt_rx++;
#endif

    return TWI_FAIL;
}


#if (VAULT_IC_TARGET == VAULTIC4XX)
/**
 * @brief   Wake up VaultIC device
 *
 * \par Description:
 *   -# Read 0 bytes at I2C address 0 (dummy read to wake up VaultIc device)
 *
 * @param   u16BusTimeout I2C bus timeout in milliseconds
 *
 */

void VltTwiDriverWakeUpVaultIc(uint16_t u16BusTimeout)
{
    // Set I2C address to 0
    if (ioctl(fd, I2C_SLAVE, 0) < 0)
    {
        LOG_ERROR("VltTwiDriverWakeUpVaultIc Failed to set slave address to 0\n");
        return ;
    }

    // Wake Up: read 0 bytes at address 0
    read(fd, NULL, 0);

    // Restore I2C address
    if (ioctl(fd, I2C_SLAVE, gu8I2cAddress) < 0)
    {
        LOG_ERROR("VltTwiDriverWakeUpVaultIc Failed to set slave address to %x\n",gu8I2cAddress);
        return ;
    }
}
#endif

static int SetBitRate(uint16_t bitrate)
{
    int file_ref =-1;
    void *map;
    i2c_reg_map_t* i2c_reg_map;

    if((file_ref = open("/dev/mem", O_RDWR | O_SYNC)) == -1) {
        return -1;
    }

    map = mmap(    NULL, //auto choose address
            sizeof(i2c_reg_map_t), //map length
            PROT_READ | PROT_WRITE, //enable read, write
            MAP_SHARED, //shared with other process
            file_ref, // file reference
            i2c_base_addr // offset to I2C1
    );

    if(map == MAP_FAILED) {
        return -1;
    }

    i2c_reg_map = (i2c_reg_map_t *)map;

    /* Set Divider */
    uint32_t divider = (GetMaxCoreClock() / (bitrate*1000))&0xFFFE;
    
    i2c_reg_map->DIV = divider;

    // Don't forget to free the mmapped memory
    if (munmap(map, sizeof(i2c_reg_map_t)) == -1) {
        return -1;
    }

    // Un-mmaping doesn't close the file, so we still need to do that
    close(file_ref);
    return 0;
}


static void SetI2CAddress(uint8_t address)
{
    // Set I2C address
    if (ioctl(fd, I2C_SLAVE, address) < 0)
    {
        LOG_ERROR("VltTwiDriverInit Failed to set slave address\n");
    }
}

static int GetRpiModel(void)
{
    #define RPI_MODEL2 "Raspberry Pi 2"
    #define RPI_MODEL3 "Raspberry Pi 3"
    #define RPI_MODEL4 "Raspberry Pi 4"

    int file_ref =-1;
    char buf[100];

    if((file_ref = open("/proc/device-tree/model", O_RDONLY )) == -1) {
        LOG_ERROR("GetRpiModel failed to open /proc/device-tree/model \n");
        return -1;
    }

    if(read(file_ref, buf, sizeof(buf)) <=0) {
        LOG_ERROR("GetRpiModel unable to read /proc/device-tree/model \n");
        return -1;
    }

    if(memcmp(buf,RPI_MODEL2, strlen(RPI_MODEL2))==0)
    {
        return RASPBERRY_PI2;
    }

    if(memcmp(buf,RPI_MODEL3, strlen(RPI_MODEL3))==0)
    {
        return RASPBERRY_PI3;
    }

    if(memcmp(buf,RPI_MODEL4, strlen(RPI_MODEL4))==0)
    {
        return RASPBERRY_PI4;
    }

    // Unsupported raspberry model
    LOG_ERROR("GetRpiModel unknown raspberry\n");
    return -1;
}

static off_t GetI2CBaseAddress(void)
{
    switch(GetRpiModel())
    {
        case RASPBERRY_PI2:
            return I2C1_BASE_PI2;

        case RASPBERRY_PI3:
            return I2C1_BASE_PI3;

        case RASPBERRY_PI4:
            return I2C1_BASE_PI4;

        default:
            return -1;
    }
}

static uint32_t GetMaxCoreClock(void)
{
    switch(GetRpiModel())
    {
        case RASPBERRY_PI2:
            return BCM_MAX_CORE_CLK_PI2;

        case RASPBERRY_PI3:
            return BCM_MAX_CORE_CLK_PI3;

        case RASPBERRY_PI4:
            return BCM_MAX_CORE_CLK_PI4;

        default:
            return -1;
    }
}

#endif //( VLT_ENABLE_TWI == VLT_ENABLE ) && ( VLT_PLATFORM == VLT_EMBEDDED)
