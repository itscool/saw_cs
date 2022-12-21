// EEPROM_FLASH.cs - EEPROM and Flash emulation aimed at larger scoped
// emulators of older hardware such as NES or SMS.
//
// This is free and unencumbered software released into the public domain.
// 
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>

//-----------------------------------------------------------------------------------------------------------
// History
// - v1.00 - 12/20/22 - Initial release by Scott Williams

//-----------------------------------------------------------------------------------------------------------
// Notes
// - Intended as reference or as direct usage in .NET-based environments.
//   If used with Unity, the code is compatible with the Burst compiler.
//
// - Error checking is essentially non-existent, so correct and safe usage must be
//   accounted for externally or added.

//-----------------------------------------------------------------------------------------------------------
// Todo
// - Multiple EEPROMs controlled by a single I2C interface

using System.Runtime.CompilerServices;

//-----------------------------------------------------------------------------------------------------------
// EEPROM
//-----------------------------------------------------------------------------------------------------------
// https://pdf1.alldatasheet.com/datasheet-pdf/view/56094/ATMEL/24C01.html
// https://pdf1.alldatasheet.com/datasheet-pdf/view/74901/MICROCHIP/24C01.html
// https://pdf1.alldatasheet.com/datasheet-pdf/view/34174/XICOR/X24C01P.html
// https://pdf1.alldatasheet.com/datasheet-pdf/view/34174/XICOR/X24C02.html
// https://krikzz.com/pub/support/everdrive-md/v2/gen_eeprom.pdf

// - Note that it appears many NES games use XICOR chips which have a 4 byte page size
// - Also note that most 24C01 chips used in games seem to be XICOR which do *not* take
//   a device/control byte after the start condition, instead directly receiving address

public unsafe struct EEPROM_I2C
{
    // I2C
    int sclPrev;
    int sdaPrev;
    int sdaWriteByte;
    int sdaBitCount;
    int sdaReadBit;
    int readMode;

    // EEPROM
    enum EEPROM_State { Standby, Control, Address, Data };
    EEPROM_State state;
    EEPROM_State stateStart;
    EEPROM_DeviceByte deviceByteMode;
    byte *prom;
    int promAddr;
    int promSizeMask;
    int promBlockMask;
    fixed byte writeRam[16];  // never > 16, this can differ between manufacturers as well as model numbers
    int writeRamAddr;
    int writeRamMask;
    int stoppedAfterWrite;  // to support potential auto-save

    public enum EEPROM_DeviceByte { NoDeviceByte, NeedsDeviceByte, DetectNoDeviceByte }

    public void Configure(byte* promBuffer, int size, int pageSize = 4, EEPROM_DeviceByte deviceByteNeeded = EEPROM_DeviceByte.NeedsDeviceByte)
    {
        prom = promBuffer;
        promSizeMask = size - 1;
        promBlockMask = size >= 256 ? 0xff : promSizeMask;  // blocks of max 256 bytes regardless of EEPROM capacity
        writeRamMask = pageSize - 1;
        promAddr = sclPrev = sdaPrev = 0;
        sdaReadBit = 1;
        state = EEPROM_State.Standby;
        stateStart = deviceByteNeeded == EEPROM_DeviceByte.NoDeviceByte ? EEPROM_State.Address : EEPROM_State.Control;
        deviceByteMode = deviceByteNeeded;
    }

    // Inputs are 0 or 1, anything else will not work correctly
    public void Write(int writeControlLow, int sda, int scl)
    {
        stoppedAfterWrite = 0;
        if (writeControlLow == 0)  // @@ Write control pin could certainly be improved...
            sdaReadBit = 1;  // no_ack
        if (sclPrev == 1 && scl == 1 && sdaPrev != sda)  // start/Stop condition
        {
            if (state == EEPROM_State.Data && readMode == 0 && sda == 1)  // stop condition after data written
            {
                // - No acknowledge polling necessary for emulation as it takes 0 extra internal time
                // - Internal write cycle doesn't occur until stop condition. While this may not always
                //   be true on all models, this logic should safely work in every case.
                // - Address roll-over for write stays in same page
                int count = writeRamAddr > writeRamMask ? (writeRamMask + 1) : writeRamAddr;
                for (int i = 0; i < count; i++)
                {
                    prom[promAddr] = writeRam[i];
                    promAddr = (promAddr & ~writeRamMask) | ((promAddr + 1) & writeRamMask);
                }
                if (count > 0)
                    stoppedAfterWrite = 1;
            }
            state = sda == 1 ? EEPROM_State.Standby : stateStart;  // can happen at any time
            writeRamAddr = sdaWriteByte = sdaBitCount = 0;
        }
        else if (state != EEPROM_State.Standby && sclPrev == 0 && scl == 1)  // only latches on rising clock edge
        {
            if (sdaBitCount < 8)
            {
                if (state == EEPROM_State.Data && readMode == 1)
                    sdaReadBit = (prom[promAddr] >> (7 - sdaBitCount++)) & 0x01;
                else
                    sdaWriteByte |= sda << (7 - sdaBitCount++);
            }
            else  // ack or not_ack read/write
            {
                sdaReadBit = 0;  // ack
                switch (state)
                {
                    case EEPROM_State.Control:
                        if ((sdaWriteByte & 0xfe) == 0b1010_000_0)
                            state = EEPROM_State.Address;  // Device Select Code, Device Address, R/W
                        else
                        {
                            if (deviceByteMode == EEPROM_DeviceByte.DetectNoDeviceByte)
                            {
                                stateStart = EEPROM_State.Address;
                                promBlockMask = promSizeMask = 0x7f;  // only known device with no device byte is X24C01 with 128 bytes of memory
                                goto case EEPROM_State.Address;
                            }
                            else
                                state = EEPROM_State.Standby;
                        }
                        readMode = sdaWriteByte & 0x01;
                        sdaReadBit = state == EEPROM_State.Standby ? 1 : 0;  // ack if not back to standby
                        break;
                    case EEPROM_State.Address:
                        state = EEPROM_State.Data;
                        promAddr = sdaWriteByte & promSizeMask;
                        break;
                    case EEPROM_State.Data:
                        // On at least Microchips's 24C01A, overflowing the (RAM) write buffer will cancel and go to standby
                        // This is the also only device with a 2 byte write buffer as far as I've seen, but honestly
                        // it may never have been used in any game carts.
                        if (writeRamAddr > writeRamMask && writeRamMask == 1)
                        {
                            state = EEPROM_State.Standby;
                            break;
                        }
                        if (readMode == 0)
                            writeRam[writeRamAddr++ & writeRamMask] = (byte)sdaWriteByte;
                        else if (sda == 0)  // check if recently read byte is externally acknowledged
                            promAddr = (promAddr & ~promBlockMask) | ((promAddr + 1) & promBlockMask);
                        break;
                }

                sdaBitCount = 0;
                sdaWriteByte = 0;
            }
        }
        sclPrev = scl;
        sdaPrev = sda;
    }

    public int Read()
    {
        return sdaReadBit;
    }

    public int IsNewDataWritten()
    {
        return stoppedAfterWrite;
    }

    public int GetSize()
    {
        return promSizeMask + 1;
    }
}


//-----------------------------------------------------------------------------------------------------------
// FLASH
//-----------------------------------------------------------------------------------------------------------
// https://ww1.microchip.com/downloads/en/DeviceDoc/20005022C.pdf

public unsafe struct FLASH_SST39SF0xx
{
    public enum DeviceType
    {
        Unknown = 0,
        SST39SF010A = 0xb5,
        SST39SF020A = 0xb6,
        SST39SF040 = 0xb7,
    }
    const int idManufacturer = 0xbf;
    DeviceType idDevice;

    fixed ushort kNextCommandAddr[5];
    fixed byte kNextCommandData[5];
    const int kCommandErase = 5;
    const int kCommandByteProgram = 100;
    int busCycle;
    int softwareIdMode;

    const int kSectorSize = 4096;
    int addressMax;
    byte* mem;
    int dataWritten;  // to support potential auto-save

    public void Configure(byte* flashMem, DeviceType type)
    {
        idDevice = type;

        kNextCommandAddr[0] = kNextCommandAddr[2] = kNextCommandAddr[3] = 0x5555;
        kNextCommandAddr[1] = kNextCommandAddr[4] = 0x2aaa;
        kNextCommandData[0] = kNextCommandData[3] = 0xaa;
        kNextCommandData[1] = kNextCommandData[4] = 0x55;
        kNextCommandData[2] = 0x80;
        busCycle = 0;
        softwareIdMode = 0;

        switch (type)
        {
            case DeviceType.SST39SF010A: addressMax = kSectorSize * 32 - 1; break;
            case DeviceType.SST39SF020A: addressMax = kSectorSize * 64 - 1; break;
            case DeviceType.SST39SF040: addressMax = kSectorSize * 128 - 1; break;
        }
        mem = flashMem;
        dataWritten = 0;
    }

    public void Write(int address, byte data)
    {
        dataWritten = 0;
        if (busCycle < 5 && kNextCommandAddr[busCycle] == address && kNextCommandData[busCycle] == data)
            busCycle++;
        else if (softwareIdMode != 0 && busCycle == 0 && data == 0xf0)
            softwareIdMode = 0;
        else if (busCycle == 2 && address == 0x5555)
        {
            busCycle = 0;
            if (softwareIdMode != 0)
                softwareIdMode = (data == 0xf0) ? 0 : 1;
            else if (data == 0xa0)
                busCycle = kCommandByteProgram;
            else if (data == 0x90)
                softwareIdMode = 1;
        }
        else if (busCycle == kCommandErase /* 5 */)
        {
            busCycle = 0;  // by this point, both valid and invalid commands will next reset the mode
            if (data == 0x30)
            {
                byte* p = mem + (address & ~kSectorSize & addressMax);
                for (byte* pEnd = p + kSectorSize; p < pEnd; p++)
                    *p = 0xff;
            }
            else if (address == 0x5555 && data == 0x10)
                for (int i = 0; i <= addressMax; i++)
                    mem[i] = 0xff;
        }
        else if (busCycle == kCommandByteProgram)
        {
            busCycle = 0;
            mem[address] &= data;
            dataWritten = 1;
        }
        else  // invalid command
            busCycle = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte Read(int address)
    {
        if (softwareIdMode == 0)  // most common case
            return mem[address & addressMax];
        if (address == 0)
            return idManufacturer;
        else if (address == 1)
            return (byte)idDevice;
        return 0xff;  // @@ Not sure what you get back from other addresses during softwareIdMode
    }

    public int IsNewDataWritten()
    {
        return dataWritten;
    }

    public int GetSize()
    {
        return addressMax + 1;
    }
}
