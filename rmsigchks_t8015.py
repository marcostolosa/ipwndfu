import dfu
import usbexec
import sys
import usb.core
import struct
import binascii

HOST2DEVICE = 0x21
DEVICE2HOST = 0xA1

DFU_DNLOAD = 1
DFU_ABORT = 4

def main():
    print "*** SecureROM t8015 sigcheckpath by tihmstar ***"
    device = dfu.acquire_device()
    print "Found:", device.serial_number
    if not "PWND:[" in device.serial_number:
        print "Please enable pwned DFU Mode first."
        sys.exit(1)
    if not "PWND:[checkm8]" in device.serial_number:
        print "Only devices pwned using checkm8 are supported."
        sys.exit(1)
    dfu.release_device(device)

    device = usbexec.PwnedUSBDevice()

    device.write_memory(0x000000018000c400,binascii.unhexlify("2506000001000000")) #clear write bit
    device.execute(0,0x1000004F0) #memory barrier
    device.execute(0,0x1000004AC) #flush tlb

    #patch codesigs
    device.write_memory(0x000000010000624c,"\x00\x00\x80\xD2") #patch sigcheck

    device.write_memory(0x000000010000db98,"\xC0\x03\x5F\xD6") #disable heap corruption check

    device.execute(0,0x1000004F0) #memory barrier

    print("done remapping and patching page")
    device = dfu.acquire_device()

    device.ctrl_transfer(HOST2DEVICE, DFU_ABORT, 0, 0, 0, 0)
    # Perform USB reset
    try:
        dfu.usb_reset(device)
        dfu.release_device(device)
    except:
        pass
    print "Device is now ready to accept unsigned images"


if __name__ == "__main__":
	main()
