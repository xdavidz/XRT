/**
 * Copyright (C) 2021 Xilinx, Inc
 * Author: Yidong Zhang
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <unistd.h>

#include "xapuversal.h"

/**
 * @brief XAPUVER_Flasher::XAPUVER_Flasher
 */
XAPUVER_Flasher::XAPUVER_Flasher(std::shared_ptr<pcidev::pci_device> dev)
{
    mDev = dev;
}

/**
 * @brief XQSPIPS_Flasher::~XQSPIPS_Flasher
 */
XAPUVER_Flasher::~XAPUVER_Flasher()
{
}

int XAPUVER_Flasher::xclUpgradeFirmware(std::istream& binStream)
{
    int total_size = 0;
    std::string errmsg;

    /* enable apu pdi flash */
    mDev->sysfs_put("xfer_versal", "apu_pdi", errmsg, "1");
    if (!errmsg.empty()) {
        std::cout << errmsg << std::endl;
        return -ENODEV;
    }

    binStream.seekg(0, binStream.end);
    total_size = binStream.tellg();
    binStream.seekg(0, binStream.beg);

    std::cout << "INFO: ***APU PDI has " << total_size << " bytes" << std::endl;
    int fd = mDev->open("xfer_versal", O_RDWR);

    if (fd == -1) {
        std::cout << "ERROR Cannot open ospi_versal for writing " << std::endl;
        /* disable apu pdi flash */
    	mDev->sysfs_put("xfer_versal", "apu_pdi", errmsg, "0");
        return -ENODEV;
    }

    std::unique_ptr<char> buffer(new char[total_size]);
    binStream.read(buffer.get(), total_size);

    ssize_t ret = write(fd, buffer.get(), total_size);

    mDev->close(fd);
    /* disable apu pdi flash */
    mDev->sysfs_put("xfer_versal", "apu_pdi", errmsg, "0");

    return ret == total_size ? 0 : -EIO;
}
