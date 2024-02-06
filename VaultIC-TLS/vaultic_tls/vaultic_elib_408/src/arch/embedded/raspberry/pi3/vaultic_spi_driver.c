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
 * @brief   VaultIC_API SPI driver
 *
 * @details
 *
 */

#include "vaultic_config.h"
#if( VLT_ENABLE_SPI == VLT_ENABLE ) && ( VLT_PLATFORM == VLT_EMBEDDED)

#if( VLT_ENABLE_TWI == VLT_ENABLE )
#error "TWI and SPI drivers can not enabled together"
#endif

#include "vaultic_typedefs.h"
#include "vaultic_timer_delay.h"
#include "vaultic_spi_driver.h"
#include <string.h>

#ifdef RPI_PRINT_ERRORS
#include <stdio.h>
#define LOG_ERROR(...) printf(__VA_ARGS__)
#else
#define LOG_ERROR(...) do { } while(0);
#endif

#ifdef SPI_TRACE_ERRORS
uint32_t spi_total_err_cnt_tx=0;
uint32_t spi_total_err_cnt_rx=0;
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>			//Needed for SPI port
#include <linux/spi/spidev.h>	//Needed for SPI driver
#define SPI_DEVICE "/dev/spidev0.0"
uint8_t spiMode = SPI_MODE_0;
uint8_t spiBits = 8;
uint32_t spiBaud;

static int fd = -1;

#define SPI_POLLING_BYTE      	(VLT_U8)0xC0


/**
 * @brief   Initialize SPI driver
 *
 * @param   u16BitRate	   bit rate (in kbits)
 * @return 	SPI_OK or SPI_FAIL
 */

uint16_t VltSpiDriverInit(uint16_t u16BitRate)
{
    // Configure SPI mode
	fd = open(SPI_DEVICE, O_RDWR);
    if (fd == -1) {
    	LOG_ERROR("VltSpiDriverInit Failed to open %s \n",SPI_DEVICE);
        return SPI_FAIL;
    }

    if (ioctl(fd, SPI_IOC_WR_MODE, &spiMode) < 0)
    {
		LOG_ERROR("Unable to configure spi write mode. Is the module properly loaded?\n");
		close(fd);
		return SPI_FAIL;
    }

    if (ioctl(fd, SPI_IOC_RD_MODE, &spiMode) < 0)
    {
		LOG_ERROR("Unable to configure spi read mode. Is the module properly loaded?\n");
		close(fd);
		return SPI_FAIL;
    }

    if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &spiBits) < 0)
    {
    	LOG_ERROR("Unable to configure spi write 8 bits. Is the module properly loaded?\n");
    	close(fd);
    	return SPI_FAIL;
    }

    if (ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &spiBits) < 0)
	{
    	LOG_ERROR("Unable to configure spi read 8 bits. Is the module properly loaded?\n");
		close(fd);
		return SPI_FAIL;
	}

    // Set baudrate
    spiBaud = u16BitRate* 1000;
	if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &spiBaud) < 0)
	{
		LOG_ERROR("Unable to configure spi max speed. Is the module properly loaded?\n");
		close(fd);
		return SPI_FAIL;
	}
	if (ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &spiBaud) < 0)
	{
		LOG_ERROR("Unable to configure spi max speed. Is the module properly loaded?\n");
		close(fd);
		return SPI_FAIL;
	}

    return SPI_OK;
}

/**
 * @brief   Deinitialize SPI driver
 *
 */
void VltSpiDriverDeInit(void)
{
	if (fd !=-1 ) close(fd);
  	fd = -1;
}

/**
 * @brief   Send bytes over the Spi interface
 *
 * @param   pu8BytesToSend   	buffer holding the data to send
 * @param   u16NumBytesToSend 	number of bytes to send
 *  @param   u32BusTimeOut 		communication timeout in ms
 *
 * @return SPI_OK or SPI_FAIL
 *
 */
uint16_t VltSpiDriverSendBytes(const uint8_t * pu8BytesToSend, uint16_t u16NumBytesToSend, uint32_t u32BusTimeOut)
{
	(void) u32BusTimeOut; // unused parameter
    
    char rec_buffer[300]; // big buffer to avoid using dynamic allocation (reasonable size for a raspberry)

	struct spi_ioc_transfer spi_transfer={0};
	spi_transfer.tx_buf = (unsigned) pu8BytesToSend;
	spi_transfer.rx_buf = (unsigned) rec_buffer;
	spi_transfer.len = u16NumBytesToSend;
	spi_transfer.speed_hz = spiBaud;
	spi_transfer.delay_usecs = 0;
	spi_transfer.bits_per_word = spiBits;
	spi_transfer.cs_change = 0;

	// send all bytes
	if (ioctl(fd, SPI_IOC_MESSAGE(1), &spi_transfer) != u16NumBytesToSend)
	{
		LOG_ERROR("**SPI Transmit error \n");

	#ifdef SPI_TRACE_ERRORS
		spi_total_err_cnt_tx++;
	#endif
		return SPI_FAIL;
	}

	// check poll bytes received
	for (int i=0; i < u16NumBytesToSend; i++)
	{
		if(rec_buffer[i]!= SPI_POLLING_BYTE)
		{
			LOG_ERROR("**SPI Transmit error : wrong polling byte received\n");

	#ifdef SPI_TRACE_ERRORS
			spi_total_err_cnt_tx++;
	#endif
			return SPI_FAIL;
		}
	}

	return SPI_OK;
}


/**
 * @brief   Receives bytes from the device.
 *
 * \par Description:
 *   -# Receive the specified number of bytes in the given buffer.
 *
 * @param   pu8Buffer		 		buffer that will hold the data to receive
 * @param   u16NumBytesToReceive 	number of bytes to receive
 * @param 	u32BusTimeOut			bus communication timeout in milliseconds
 *
 * @return SPI_OK or SPI_FAIL
 *
 */
uint16_t VltSpiDriverReceiveBytes(uint8_t * pu8Buffer, uint16_t u16NumBytesToReceive, uint32_t u32BusTimeOut)
{
    (void) u32BusTimeOut; // unused parameter
    
    char tx_buffer[300]; // big buffer to avoid using dynamic allocation (reasonable size for a raspberry)

	// Construct buffer containing the number of polling bytes required to receive all data
	memset(tx_buffer, SPI_POLLING_BYTE, u16NumBytesToReceive);

	struct spi_ioc_transfer spi_transfer={0};
	spi_transfer.tx_buf = (unsigned) tx_buffer;
	spi_transfer.rx_buf = (unsigned) pu8Buffer;
	spi_transfer.len = u16NumBytesToReceive;
	spi_transfer.speed_hz = spiBaud;
	spi_transfer.delay_usecs = 0;
	spi_transfer.bits_per_word = spiBits;
	spi_transfer.cs_change=0;

	if (ioctl(fd, SPI_IOC_MESSAGE(1), &spi_transfer) != u16NumBytesToReceive)
	{
		LOG_ERROR("**SPI Receive error \n");

	#ifdef SPI_TRACE_ERRORS
		spi_total_err_cnt_rx++;
	#endif

		return SPI_FAIL;
	}

	return SPI_OK;
}


/**
 * @brief   Drive SPI Slave Select pin to low
 */
void VltSpiSlaveSelectLow()
{
	// Nothing to do (already managed by rpi)
}


/**
 * @brief   Drive SPI Slave Select pin to high
 */
void VltSpiSlaveSelectHigh()
{
	// Nothing to do (already managed by rpi)
}

#endif
