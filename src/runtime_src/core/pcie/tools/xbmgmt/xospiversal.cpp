/**
 * Copyright (C) 2019 Xilinx, Inc
 * Author: Larry Liu
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
#include <thread>
#include <chrono>

#include "xospiversal.h"

/**
 * @brief XOSPIVER_Flasher::XOSPIVER_Flasher
 */
XOSPIVER_Flasher::XOSPIVER_Flasher(std::shared_ptr<pcidev::pci_device> dev)
{
    mDev = dev;
    percentage = 0;
    totalSize = 0;
}

/**
 * @brief XQSPIPS_Flasher::~XQSPIPS_Flasher
 */
XOSPIVER_Flasher::~XOSPIVER_Flasher()
{
}

int XOSPIVER_Flasher::xclUpgradeFirmware(std::istream& binStream)
{
    int total_size = 0;

    binStream.seekg(0, binStream.end);
    total_size = binStream.tellg();
    binStream.seekg(0, binStream.beg);

    std::cout << "INFO: ***PDI has " << total_size << " bytes" << std::endl;
    int fd = mDev->open("ospi_versal", O_RDWR);

    if (fd == -1) {
        std::cout << "ERROR Cannot open ospi_versal for writing " << std::endl;
        return -ENODEV;
    }

    std::unique_ptr<char> buffer(new char[total_size]);
    binStream.read(buffer.get(), total_size);

    auto worker = [&](){
        totalSize = write(fd, buffer.get(), total_size);
	percentage = 100;
    };

    std::thread thread_flash(worker);

    while (percentage <= 100) {
        std::cout << ".";
        std::this_thread::sleep_for(std::chrono::seconds(5));
    };
    thread_flash.join();

    mDev->close(fd);

    return totalSize == total_size ? 0 : -EIO;
}
