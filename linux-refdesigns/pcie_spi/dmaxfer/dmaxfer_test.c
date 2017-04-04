/*
 * Copyright Altera Corporation (C) 2013, 2015. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "exports.h"

#define AVERAGE_LOOP		3
#define PATTERN_MASK_A		0x5A5A5A5A
#define PATTERN_MASK_B		0xA5A5A5A5

#define RPDMA_DEV	"/dev/blkrpdma0"
#define EPDMA_DEV	"/dev/blkepdma0"

#define PCIERP_DEBUG
#ifdef PCIERP_DEBUG
#define PRINT_BYTES		0x100
static void dump_mismatch(char *tx_data, char *rx_data, unsigned int datlen)
{
	int i;
	unsigned int mismatch = 0;
	unsigned int firstmismatch;

	/* find mismatch */
	for (i = 0; i < datlen; i++) {
		if ((char)(*(tx_data + i)) != (char)(*(rx_data + i))) {
			if (mismatch == 0)
				firstmismatch = i;
			mismatch++;
		}
	}

	/* total mismatch */
	printf("Total size 0x%x and mismatch 0x%x bytes\n", datlen, mismatch);

	/* print first 256 bytes */
	if (mismatch > PRINT_BYTES)
		mismatch = PRINT_BYTES;

	/* print send data */
	printf("\nFirst 0x%x mismatch transmit data", PRINT_BYTES);
	for (i = firstmismatch; i < firstmismatch + PRINT_BYTES; i++) {
		if (!(i & 0xf) ||
		    ((i == firstmismatch) && (firstmismatch & 0xf)))
			printf("\nOffset %08x  ", i);
		printf("%02x ", (char)(*(tx_data + i)));
	}

	/* print receive data */
	printf("\n\nFirst 0x%X mismatch received data", PRINT_BYTES);
	for (i = firstmismatch; i < firstmismatch + PRINT_BYTES; i++) {
		if (!(i & 0xf) ||
		    ((i == firstmismatch) && (firstmismatch & 0xf)))
			printf("\nOffset %08X  ", i);
		printf("%02x ", (char)(*(rx_data + i)));
	}

	printf("\n\n");
}
#endif

static int get_xfer_size(unsigned int *rpdatlen, unsigned int *epdatlen)
{
	int err = 0;
	int fdrp;
	int fdep;

	/* read EP DMA transfer size */
	fdep = open(EPDMA_DEV, O_RDWR | O_SYNC);
	if (fdep < 0) {
		printf("Failed to open %s\n", EPDMA_DEV);
		return -ENODEV;
	}
	err = ioctl(fdep, GET_SIZE_IOCTL, epdatlen);
	if (err < 0) {
		printf("Device %s failed to read size\n", EPDMA_DEV);
		goto err_close_fdep;
	}

	fdrp = open(RPDMA_DEV, O_RDWR | O_SYNC);
	if (fdrp < 0) {
		printf("Failed to open %s\n", RPDMA_DEV);
		/* No error return, continue for simplified RP design */
		*rpdatlen = *epdatlen;
		goto err_close_fdep;
	}

	err = ioctl(fdrp, GET_SIZE_IOCTL, rpdatlen);
	if (err < 0)
		printf("Device %s failed to read size\n", RPDMA_DEV);

	close(fdrp);
err_close_fdep:
	close(fdep);
	return err;
}

static void fill_pattern(unsigned int *ptr, unsigned int size,
			 unsigned int start_ptn)
{
	unsigned int i;
	unsigned int word = size / sizeof(unsigned int);

	for (i = 0; i < word; i++) {
	//	printf("fill_pattern data are:= %x\n\r",start_ptn);
		*ptr = start_ptn++;
		ptr++;
	}

}

static unsigned int dma_xfer(int is_rp, unsigned int ioctlno, unsigned int ptn,
			     unsigned int datlen)
{
	int fd;
	char *tx_data;
	char *rx_data;
	unsigned int timediff;
	char *dev_str;

	if (is_rp)
		dev_str = RPDMA_DEV;
	else
		dev_str = EPDMA_DEV;

	timediff = 0;
	/* open and set command */
	fd = open(dev_str, O_RDWR | O_SYNC);
	if (fd < 0) {
		printf("Failed to open %s\n", dev_str);
		return 0;
	}

	if (ioctl(fd, SET_CMD_IOCTL, &ioctlno) < 0) {
		printf("Device %s failed to set ioctl command\n", dev_str);
		goto err_close_fd;
	}

	tx_data = calloc(datlen, sizeof(char));
	if (!tx_data) {
		printf("Error allocate transmit memory\n");
		goto err_close_fd;
	}
	rx_data = calloc(datlen, sizeof(char));
	if (NULL == rx_data) {
		printf("Error allocate receive memory\n");
		goto err_close_tx_data;
	}

	fill_pattern((unsigned int *)tx_data, datlen, ptn);
	if (lseek(fd, 0, SEEK_SET) < 0) {
		printf("Device %s failed to seek head\n", dev_str);
		goto err_close_rx_data;
	}
	if (write(fd, tx_data, datlen) < 0) {
		printf("Device %s failed to write\n", dev_str);
		goto err_close_rx_data;
	}
	/* initiate transfer and get the time elapse */
	if (ioctl(fd, ioctlno, &timediff) < 0) {
		printf("Device %s ioctl failed to transfer\n", dev_str);
		goto err_close_rx_data;
	}

	/* successful DMA transfer */
	if (timediff) {
		if (lseek(fd, 0, SEEK_SET) < 0) {
			printf("Device %s failed to seek head\n", dev_str);
			goto err_close_rx_data;
		}

		if (read(fd, rx_data, datlen) < 0) {
			printf("Device %s failed to read\n", dev_str);
			goto err_close_rx_data;
		}

		/* compare data */
		if (memcmp(tx_data, rx_data, datlen)) {
			printf("Device %s Data mismatch !!!\n", dev_str);
			#ifdef PCIERP_DEBUG
			dump_mismatch(tx_data, rx_data, datlen);
			#endif
		}
	}

err_close_rx_data:
	free(rx_data);
err_close_tx_data:
	free(tx_data);
err_close_fd:
	close(fd);

	return timediff;
}

static unsigned int spi_xfer(int is_rp, unsigned int ioctlno, unsigned int address,
			     unsigned int datlen)
{

	int fd;
	unsigned int timediff;
	char *dev_str;

	if (is_rp)
		dev_str = RPDMA_DEV;
	else
		dev_str = EPDMA_DEV;

	timediff = 0;
	/* open and set command */
	fd = open(dev_str, O_RDWR | O_SYNC);
	if (fd < 0) {
		printf("Failed to open %s\n", dev_str);
		return 0;
	}
/*
	if (ioctl(fd, SET_CMD_IOCTL, &ioctlno) < 0) {
		printf("Device %s failed to set ioctl command\n", dev_str);
		goto err_close_fd;
	}
*/
	if (ioctl(fd, ioctlno, &address) < 0) {
		printf("Device %s ioctl failed to transfer\n", dev_str);
		goto err_close_fd;
	}

	
#if 0
	tx_data = calloc(datlen, sizeof(char));
	if (!tx_data) {
		printf("Error allocate transmit memory\n");
		goto err_close_fd;
	}
	rx_data = calloc(datlen, sizeof(char));
	if (NULL == rx_data) {
		printf("Error allocate receive memory\n");
		goto err_close_tx_data;
	}

	(unsigned int *) tx_data = 0x8282;

	if (lseek(fd, 0, SEEK_SET) < 0) {
		printf("Device %s failed to seek head\n", dev_str);
		goto err_close_rx_data;
	}
	if (write(fd, tx_data, datlen) < 0) {
		printf("Device %s failed to write\n", dev_str);
		goto err_close_rx_data;
	}
	/* initiate transfer and get the time elapse */

	if (ioctl(fd, ioctlno, &timediff) < 0) {
		printf("Device %s ioctl failed to transfer\n", dev_str);
		goto err_close_rx_data;
	}
#endif

err_close_fd:
	close(fd);

	return address;

}
static unsigned int do_trans(int is_rp, unsigned int ioctlno, unsigned int ptn,
			     unsigned int datlen)
{
	int loop;
	unsigned int count, total_count;
	unsigned int timediff;

	count = 0;
	total_count = 0;

	for (loop = 1 ; loop <= AVERAGE_LOOP ; loop++) {
		timediff = dma_xfer(is_rp, ioctlno, ptn + loop, datlen);
		if (timediff) {
			count++;
			total_count += timediff;
		}
	}

	if (total_count)
		return (datlen * count) / total_count;
	return 0;
}

int main(int argc, char** argv)
{
	unsigned int datlen, rpdatlen, epdatlen;
	unsigned int result;
	unsigned int return_value;
	unsigned int memory_address;
	unsigned int memory_data; 
	unsigned int memory_packet;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp("--help", argv[i]) == 0) {
			printf("Usage %s: <Memory Address> 0 ~ 4080 , <DATA> 0 ~ 65535 \n"
				, argv[0]);
			return -1;
		}
	}

	if (argc != 3) {
		printf("Usage %s: <Memory Address> 0 ~ 4080 , <DATA> 0 ~ 65535 \n"
			, argv[0]);
		return -1;
	}
	else {
		memory_address = atoi(argv[1]);
		memory_data = atoi(argv[2]);
		memory_packet = ((memory_address<<8) | memory_data);
		printf("memory packet : %x\n", memory_packet);
		if (memory_address < 0 || memory_address > 4096 ||  ((memory_address%16) != 0) ) {
			printf("Invalid Memory Address. Valid Address range is 0 ~ 4080 and have to write 16's multiple number \n");
			return -1;
		}
		if (memory_data < 0 && memory_data > 65535) {
			printf("Invalid Data. Valid input is 0 ~ 65535\n");
			return -1;
		}
	}

	
	if (get_xfer_size(&rpdatlen, &epdatlen)) {
		printf("Failed to get data transfer size\n");
		return -1;
	}

	datlen = rpdatlen < epdatlen ? rpdatlen : epdatlen;
	
	printf("datlen := %x\r\n", datlen);
	printf("rpdatlen := %x\r\n", rpdatlen);
	printf("epdatlen := %x\r\n", epdatlen);
	printf("\n");
#if 0	
	printf("==================================================\n");
	printf("PCIe throughput test\n");
	printf("  RP-OCM = Rootport On-Chip RAM\n");
	printf("  EP-OCM = Endpoint On-Chip RAM\n");
	printf("  RP-SYS = Rootport System Memory\n");
	printf("==================================================\n\n");
	printf("\t\tSource\t\tDestination\tResults (MB/s)\n");
	printf("-----------------------------------------------------------\n");

	result = do_trans(1, OCM_TX_IOCTL, PATTERN_MASK_A, datlen);
	printf("  RP-DMA TX\tRP-OCM\t\tEP-OCM\t\t%d\n", result);

	result = do_trans(1, OCM_RX_IOCTL, PATTERN_MASK_B, datlen);
	printf("  RP-DMA RX\tEP-OCM\t\tRP-OCM\t\t%d\n", result);

	result = do_trans(1, SYS_TX_IOCTL, PATTERN_MASK_A, datlen);
	printf("  RP-DMA TX\tRP-SYS\t\tEP-OCM\t\t%d\n", result);

	result = do_trans(1, SYS_RX_IOCTL, PATTERN_MASK_B, datlen);
	printf("  RP-DMA RX\tEP-OCM\t\tRP-SYS\t\t%d\n", result);

	printf("-----------------------------------------------------------\n");

	result = do_trans(0, OCM_TX_IOCTL, PATTERN_MASK_A, datlen);
	printf("  EP-DMA TX\tEP-OCM\t\tRP-OCM\t\t%d\n", result);

	result = do_trans(0, OCM_RX_IOCTL, PATTERN_MASK_B, datlen);
	printf("  EP-DMA RX\tRP-OCM\t\tEP-OCM\t\t%d\n", result);

	result = do_trans(0, SYS_TX_IOCTL, PATTERN_MASK_A, datlen);
	printf("  EP-DMA TX\tEP-OCM\t\tRP-SYS\t\t%d\n", result);

	result = do_trans(0, SYS_RX_IOCTL, PATTERN_MASK_B, datlen);
	printf("  EP-DMA RX\tRP-SYS\t\tEP-OCM\t\t%d\n", result);
#endif
	spi_xfer(0, SPI_TX_IOCTL, memory_packet, 1);
	printf("tx \n");
	return_value = spi_xfer(0, SPI_RX_IOCTL, memory_packet, 1);
	printf("Rx \n");
	printf("spi data = %x\n", return_value);
	
	return 0;
}

