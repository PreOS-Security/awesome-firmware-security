# Awesome Firmware Security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Awesome Firmware Security is a curated list of platform firmware resources, with a focus on security and testing. Created by [PreOS Security](https://preossec.com).

**_NOTE_**: IoT / embedded operating system security is not included, unless they happen to overlap with platform security, such as Intel AMT, AMD PSP, Redfish, IPMI, BMC, OpenBMC. There are already awesome IoT/embedded operating system lists. eg: [Awesome IoT](https://github.com/HQarroum/awesome-iot)

---
---

## Technologies and Terminology

Each of these technologies are awesome in their own right, and we'll make a standalone awesome list for them at some point. Meanwhile, they form our index.

* [ACPICA](https://acpica.org) - The ACPI Component Architecture Project (ACPICA) provides a collection of cross-platform ACPI tools, such as acpidump.
* [ACPI](http://uefi.org/acpi/) - ACPI is a platform firmware technology, originally intended to replace Plug and Play, MP, and Advanced Power Management. The UEFI Forum owns the spec and maintains an awesome list of ACPI-related documents.
  * [ACPICA](https://acpica.org) - The ACPI Component Architecture Project (ACPICA) provides a reference implementation, and a collection of cross-platform ACPI tools, such as acpidump.
* [ARC](https://en.wikipedia.org/wiki/Advanced_RISC_Computing) - ARC (Advanced Computing Environment) is a platform firmware technology used by early Windows NT non-Intel systems. The design of ARC was influential to the design of UEFI: firmware images on a hard disk partition, pointed to by variables.
* [BIOS](https://en.wikipedia.org/wiki/BIOS) - BIOS is a platform firmware technology initially used on the Intel-based IBM PC. It is an 8086 Real Mode technology. Intel has said that they will end-of-life BIOS-based platform firmware by 2020, replacing it with [UEFI](#uefi). Intel and a few IBVs have closed-source BIOS implementations. BIOS used to be the main firmware technology on Microsoft Windows PCs, until Windows started requiring [UEFI](#uefi).
  * [SeaBIOS](https://seabios.org) - The primary open source BIOS implementation.
* [coreboot](https://coreboot.org) - coreboot is a platform firmware technology, originally called LinuxBIOS. It loads payloads such as SeaBIOS, UEFI, among others. Widely used in embedded systems. Coreboot is used by Google on ChromeOS systems, using coreboot Verified Boot for additional security.
* [Direct Memory Access](https://en.wikipedia.org/wiki/Direct_memory_access) - DMA allows certain hardware subsystems, most notably PCIe to access main system RAM, independent of the central processing unit (CPU). Attackable by rogue hardware such as [PCIleech](https://github.com/ufrisk/pcileech/). The primary protection is [iommu](https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit) hardware and operating system support.
* [Heads](https://github.com/osresearch/heads) - Heads is a platform boot firmware payload that includes a minimal Linux that runs as a coreboot or LinuxBoot ROM payload to provide a secure, flexible boot environment.
* [Independent BIOS Vendor](https://en.wikipedia.org/wiki/BIOS#Vendors_and_products) - An Independent BIOS Vendor (IBV) provides an integrated firmware solution to OEMs/ODMs. With UEFI replacing BIOS, some IBVs now refer to themselves as IFVs, Independent Firmware Vendors. Some OEMs will outsource their consumer-class device firmware to IBVs, and do their own firmware for their business-class devices. Examples include: 
  * [AMI](https://ami.com)
  * [Insyde](https://www.insyde.com/)
  * [Phoenix](https://www.phoenix.com/)
* [Intel Boot Guard](https://en.wikipedia.org/wiki/Intel_vPro#Intel_Boot_Guard) - Intel Boot Guard is a firmware security technology that helps secure the boot process before UEFI Secure Boot takes place. Once Boot Guard is enabled, it cannot be disabled and prevents the installation of replacement firmware such as coreboot.
* [JTAG](https://en.wikipedia.org/wiki/JTAG) - JTAG is a hardware interface to chips that allows access to the firmware. It is used by firmware engineers during devlopment, and by Evil Maid attackers when the vendor leaves the JTAG interface exposed in consumer devices.
* [LAVA](https://validation.linaro.org/) - LAVA is an automated validation architecture primarily aimed at testing deployments of systems based around the Linux kernel on ARM devices, specifically ARMv7 and later.
* [LinuxBoot](https://www.linuxboot.org/) - LinuxBoot is a platform firmware boot technology that replaces specific firmware functionality like the UEFI DXE phase with a Linux kernel and runtime.
* [Management Mode](https://www.uefi.org/sites/default/files/resources/UEFI_Plugfest_March_2016_AMI.pdf) - Management Mode is term used by UEFI to refer to both Intel SMM and ARM TrustZone. A privileged execution mode of the CPU.
* Management systems are implemented on a separate processor, and often a dedicated network interface, facilitating out of band access and control. In some cases such as Intel ME and AMD PSP the management processor is on the same die as the primary CPU. These systems often use a full embedded OS, such as BSD or Linux.
  * [AMD PSP](https://en.wikipedia.org/wiki/AMD_Platform_Security_Processor) - The AMD PSP (Platform Security Processor) is a security processor on AMD systems, which runs firmware applications such as fTPM.
  * [Apple T2](https://www.apple.com/imac-pro/) - System management controller, image signal processor, SSD controller and secure enclave for encrypted storage and secure boot for the imac pro.
  * [Baseboard Management Controller](https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface#Baseboard_management_controller) A BMC is an interface to manage server firmware, including applying updates. [OpenBMC](https://github.com/openbmc/openbmc) is the main open source BMC implementation.
  * [DASH](http://www.dmtf.org/standards/dash/) - DMTF DASH is an out-of-band firmware management specification for desktops. [Intel AMT](https://software.intel.com/en-us/articles/developing-for-intel-active-management-technology-amt) is a compliant implementation of DASH, as is AMD SIMFIRE.
  * [Intel AMT](https://software.intel.com/en-us/articles/developing-for-intel-active-management-technology-amt) - Intel AMT is a platform firmware management technology on Intel systems, running on the Intel ME processor as an application. AMT provides services such as remote KVM, power control, bare-metal OS restore and re-imaging, and remote alerting.
  * [Intel ME](https://en.wikipedia.org/wiki/Intel_Management_Engine) - Intel ME is a management and security processor on Intel systems, which runs Intel Active Management Technology AMT, Advanced Fan Speed Control, Boot Guard & Secure Boot, Serial over LAN and firmware-based TPM (fTPM). Appears to run a variant of MINIX.
  * [IPMI](https://www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html) - IPMI is a platform firmware management technology, typically on Intel or AMD server systems. Often implemented as an embedded Linux.  While widely-used, the modern replacement for IPMI is [Redfish](http://dmtf.org/standards/redfish/).
  * [OpenBMC](https://github.com/openbmc/openbmc) - The OpenBMC project is a Linux distribution for embedded devices that have a BMC.
  * [Redfish](http://dmtf.org/standards/redfish/) - DMTF Redfish is an out-of-band firmware management technology, replacing [IPMI](https://www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html)
  * [SMASH](http://dmtf.org/standards/smash/ ) - DMTF DASH is an out-of-band firmware management specification for servers, similar to DASH.
* [Measured Boot](https://firmware.intel.com/blog/security-technologies-and-minnowboard-max) - Intel technology using TCG TPMs to secure the boot process.
* [Microcode](https://en.wikipedia.org/wiki/Microcode) - Microcode is a form of firmware for the CPU. Systems need microcode updates just like they need platform firmware updates, and OS updates.
* [NIST](https://csrc.nist.gov/) - a standards-setting body for the US government. Has several security for design and operations relating to firmware in [Documentation, Books and Training](#documentation-books-and-training) 
* [Original Equipment Manufacturer](https://en.wikipedia.org/wiki/Original_equipment_manufacturer) - An OEM builds and sells original hardware.
* [Original Design Manufacturer](https://en.wikipedia.org/wiki/Original_design_manufacturer) - An ODM builds hardware and sells them to OEMs.
* [Operating System Vendor](https://en.wikipedia.org/wiki/Operating_system) - An OSV is an Operating System Vendor, which includes firmware/OS interactions.
* [Option ROM](https://en.wikipedia.org/wiki/Option_ROM) - An Option ROM, aka an Expansion ROM, aka OpROM, aka XROM, is the firmware 'blob' of a PCI/PCIe device. An Option ROM is terminology from BIOS era, when a card would hook the BIOS platform firmware and add additional functionality for the new card. An Option ROM is a BIOS/UEFI driver on the card's flash. A card may need multiple drivers, one for each architecture and one for each platform firmware type (BIOS+x86_64, BIOS+ARM, UEFI+x86_64, UEFI+ARM, etc). Option ROMs do not account for all of the firmware on such a device, as the operating firmware for the device function such as RAID, or TCP offloading may be entirely separate.
* [PCIe](https://pcisig.com/) - PCIe is the interface for PC boards. PCIe devices include Option ROMs of firmware. The device may have a processor invisible to the system board, it is difficult to fully trust PCIe hardware.
* [Secure Boot](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface#Secure_boot) - Secure Boot is a term often associated with UEFI Secure Boot, an optional security feature of UEFI that helps secure the boot process. It does not require a TPM. Besides UEFI, other firmware technologies also use the term Secure Boot, sometimes in lower case. The Apple EFI-based Secure Boot implementation is not the same as the Secure Boot technology used by Windows/Linux systems.
* [SMM](https://en.wikipedia.org/wiki/System_Management_Mode) - Systems Management Mode (SMM) is a processor mode in Intel and AMD systems, separate from Real and various Protect Modes, that gives full control of the processor. SMM-hosted applications, such as malware, is invisible to the normal Protect Mode-based code.
* [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface_Bus) - SPI is an interface to accessing the firmware. Used by vendors during development, and used by attackers if left enabled in consumer products.
* [Trusted Execution Environment](https://en.wikipedia.org/wiki/Trusted_execution_environment) - also known as Secure Execution Environment (SEE). An example of a hypervisor or other technology that constrains firmware to be more secure. ARM TrustZone is an example of a SEE.
* [Thunderbolt](https://www.intel.com/content/www/us/en/io/thunderbolt/thunderbolt-technology-general.html) - a external peripheral hardware interface developed by Intel and Apple. Combines [PCIe](https://pcisig.com/), DisplayPort and DC power.
* [Tianocore](https://tianocore.org/) - Tianocore is the home to the UEFI Forum's open source implementation. Vendors use this code, along with closed-source drivers and value-added code.
* [TrustZone](https://www.arm.com/products/security-on-arm/trustzone) - TrustZone (TZ) is a firmware security technology used on ARM systems, a form of TEE/SEE, called Management Mode by UEFI.
* [TPM](http://www.trustedcomputinggroup.org/) - A TPM is the root-of-trust for many platform firmware implementations, such as Intel/AMD BIOS and UEFI systems. TPM is defined by the Trustworthy Computing Group (TCG). There are discrete TPM chips, as well as "soft" firmware TPM implementations called fTPM, provided by eg: Intel ME, AMD PSP.
* [Trusted Boot](https://trustedcomputinggroup.org/trusted-boot/) - Trusted Boot is a firmware security technology from the Trustworthy Computing Group, which uses TPMs to help secure the boot process.
* [Trustworthy Computing Group](http://www.trustedcomputinggroup.org/) - Trustworthy Computing Group (TCG) is an industry trade group that controls the TPM and related specifications.
* [U-Boot](https://www.denx.de/wiki/U-Boot/) - U-Boot loads payloads such as SeaBIOS, UEFI, among others. U-Boot and coreboot are widely used in embedded systems.
* [UEFI](https://uefi.org) -  UEFI is a platform firmware technology initially created by Intel, now used by Intel, AMD, ARM, and others, which was initially designed for the Intel Itanium and as a replacement for BIOS. UEFI is also EFI. UEFI-based platform firmware technology is often referred to as BIOS, with the older BIOS called Legacy Mode or CSM (Compatibility Support Mode).
* [UEFI DBX](https://www.uefi.org/revocationlistfile) - The UEFI DBX UEFI Secure Boot blacklist file contains the latest UEFI Secure Boot PKI blacklist/expired keys. Check your vendor documentation to see how your system's vendor tools work to obtain and apply this to your system; if the vendor has no tools, ask them to provide them.
* [UEFI Forum](https://uefi.org/) - The UEFI Forum is an industry trade group that controls the UEFI and ACPI specifications, the UEFI SCT tests, and provides the Tianocore open source UEFI implementation.
* [USB](http://www.usb.org ) - Universal Serial Bus (USB) is an industry standard for external peripheral devices. USB devices can be configured to be multiple devices, and rogue USB hardware like Hak5's [Rubber Ducky](https://hakshop.com/products/usb-rubber-ducky-deluxe) can trick naive operating systems.
* [Verified Boot](https://source.android.com/security/verifiedboot/) - Verified Boot is a firmware security technology from Google, that helps secure the boot process. Roughly equivalent to Secure Boot.
  * [Android Verified Boot](https://source.android.com/security/verifiedboot/) - Android version of Verified Boot
  * [ChromeOS Verified Boot](https://www.chromium.org/chromium-os/chromiumos-design-docs/verified-boot) - ChromiumOS and ChromeOS version of Verified Boot.

---

## Threats

* [BadBIOS](https://en.wikipedia.org/wiki/BadBIOS) - BadBIOS is the alleged firmware malware reported by Dragos.
* [Evil Maid Attack](https://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html) - The Evil Maid attack is perhaps the most well-known firmware attack, where the victim leaves their sstem unattended and an attacker has some period of time with physical access to the system, for them to install firmware-level malware. For example, person leaves their laptop in their hotel room while out for dinner, and the attacker is posing as hotel room service.
* [Hacking Team UEFI Malware](https://attack.mitre.org/wiki/Software/S0047) - acking Team is a company that sells exploits to governments and others. Amongst their offerings is a UEFI-based firmware attack for Windows PCs. The Hacking Team malware is one of the few existing known public UEFI blacklisted by [CHIPSEC](https://github.com/chipsec/chipsec).
* [Fish2 IPMI Security](http://www.fish2.com/ipmi/) - a compilation of information about poor and/or insecure IPMI implementations. 
* [PCI Leech](https://github.com/ufrisk/pcileech/) - PCILeech is PCI-based rogue hardware used to attack PCI interfaces of systems. Defense is [iommu](https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit) in combination with operating system iommu support.
* [Rowhammer](https://en.wikipedia.org/wiki/Row_hammer) - Rowhammer is a new form of memory-based security attacks against systems. Defense is ECC memory.
* [ThinkPwn](https://github.com/Cr4sh/ThinkPwn) - ThinkPwn is a UEFI malware PoC that originally targets ThinkPad systems. The ThinkPwn malware is one of the few existing known public UEFI blacklisted by CHIPSEC. Thinkpwn.efi is included in FPMurphy's UEFI Utilities, one malware binary amongst other useful tools, be careful if using those tools.
* [USB Rubber Ducky](https://hakshop.com/products/usb-rubber-ducky-deluxe) - a Rubber Ducky is an example of rogue USB hardware, which lets the user configure the system to trick naive operating systems into thinking it is any number of devices.

---

## Tools

* [ACPICA tools](https://acpica.org/downloads) - provides tools and a reference implementation of ACPI.
* [acpidump](https://acpica.org/) - Cross-platform OS-present tool from ACPICA to dump and diagnose ACPI tables.
* [BIOS Implementation Test Suite](https://biosbits.org/) - The Intel BIOS Implementation Test Suite (BITS) provides a bootable pre-OS environment for testing BIOSes and in particular their initialization of Intel processors, hardware, and technologies. It includes a CPython compiled as a raw BIOS application.
* [DarwinDumper](https://bitbucket.org/blackosx/darwindumper) - DarwinDumper is an open source project which is a collection of scripts and tools to provide a convenient method to quickly gather a system overview of your OS X System.
* [Eclipse UEFI EDK2 Wizards Plugin](https://github.com/ffmmjj/uefi_edk2_wizards_plugin) - This Eclipse plugin helps EDK2 developers use the Eclipse IDE with CDT for doing UEFI development. 
* [EFIgy](https://efigy.io) - Duo Security's EFIgy is an open source Apple Mac-centric tool that checks if the system has the most up-to-date EFI firmware.
* [Firmadyne](https://github.com/firmadyne/firmadyne) - Firmadyne is an automated and scalable system for performing emulation and dynamic analysis of Linux-based embedded firmware. 
* [Firmware.re](http://firmware.re/) - Firmware.RE is a free service that unpacks, scans and analyzes almost any firmware package and facilitates the quick detection of vulnerabilities, backdoors and all kinds of embedded malware.
* [GRUB](https://www.gnu.org/software/grub/) - GRUB is a Multiboot boot loader. It compiles as a BIOS or a UEFI application.
* [Linux Shim](https://github.com/rhboot/shim) - The Shim is a UEFI boot loader, which loads another UEFI boot loader, perhaps with a different license, and signed by another vendor. There are multiple forks of Shim in the wild.
  * [Fedora Guide to UEFI Secure Boot Shim](https://docs-old.fedoraproject.org/en-US/Fedora/18/html/UEFI_Secure_Boot_Guide/sect-UEFI_Secure_Boot_Guide-Implementation_of_UEFI_Secure_Boot-Shim.html)
* [Linux Stub](https://www.kernel.org/doc/Documentation/efi-stub.txt) - The Linux kernel can be built so that the kernel is both a BIOS and a EFI boot loader. 
* [CHIPSEC](https://github.com/chipsec/chipsec) - CHIPSEC is a security tool created by Intel, to test the security posture of Intel BIOS / UEFI. Currently the only tool that can check for multiple public firmware security vulnerabilities. 
* [eficheck](https://apple.com) - sadly lacking an awesome link for this, as this tool is only available on recent versions MacOS, and not documented at https://apple.com. Verifies UEFI integrity and security.
* [Firmware Test Suite](https://launchpad.net/fwts) - FirmWare Test Suite (FWTS) is a collection of firmware tests created by [Canonical](https://canonical.com), the [Ubuntu](https://ubuntu.com) Linux OSV, to help test a system for defects that will cause [Ubuntu](https://ubuntu.com) problems. FWTS is a suite of dozens of tests, for multiple technologies. The UEFI Forum recommends FWTS as the main ACPI test resource. FWTS is a command line tool for Linux, and includes an optional CURSES UI, and an optional FWTS-live live-boot distribution. FWTS is included in Intel's LUV Linux distribution.
* [FlashROM](https://flashrom.org/Flashrom) - FlashROM is a Linux/BSD-centric utility a utility for identifying, reading, writing, verifying and erasing flash chips. It is designed to flash BIOS/EFI/coreboot/firmware/optionROM images on mainboards, network/graphics/storage controller cards, and various other programmer devices. Partial Windows support is available.
* [Golden Image](https://en.wikipedia.org/wiki/System_image) - A golden image is the vendor's original binaries for the firmware. The term is also used for OS images. Better vendors provide images and tools to reset used hardware/grey market acquisitions to a known state. Before trusting any downloaded binary, such as a golden image, it should be compared to a hash. Most vendors do not provide a hash for their images.
* [Linux UEFI Validation](https://01.org/linux-uefi-validation) - LUV is a Linux distro created by Intel to test UEFI implementation of OEMs. It bundles CHIPSEC, FWTS, and other firmware tests. LUV is available in binary form as LUV-live, a live-boot distribution.
* [Linux Vendor Firmware Services](https://fwupd.org/) - aka: LVFS or fwupd, a firmware update service for Linux OEMs. AWESOMELY provides a standardized system. OEMs that use this are taking Linux compatibility and security seriously. On Microsoft Windows, a similar approach works through Windows Update.
* [Microsoft Windows Update](https://en.wikipedia.org/wiki/Windows_Update) - surprise - Windows Update is awesome! In addition to doing OS software-level updates, Windows Update can do firmware updates via standardized capsules. These updates must be verified by the firmware / hardware vendor, and can be EV signed.
* [Pawn](https://github.com/google/pawn) - Google Pawn is a Linux-centric online firmware tool that dumps the platform firmware image to a file, for later offline analysis.
* [rEFInd](http://www.rodsbooks.com/refind/) - rEFInd is the successor to rEFIt, a UEFI boot loader that lets you select multiple operating systems. 
* [RU.EFI](https://github.com/JamesAmiTw/ru-uefi/) - RU.EFI is a third-party freeware firmware tool that has multiple features. It works as a MS-DOS or UEFI Shell utility.
* [RWEverything](http://rweverything.com/) - RWEverything (RWE) is a third-party freeware firmware tool that has multiple features. The tools works on Windows. The CHIPSEC tool, if the CHIPSEC Windows kernel driver is not loaded, can use the RWE kernel driver.
* [Sandsifter](https://github.com/xoreaxeaxeax/sandsifter) - Sandsifter is an x86 fuzzer.
* [UEFI Utilities](https://github.com/fpmurphy/UEFI-Utilities-2018) - UEFI Utilities is a collection of UEFI Shell utilities that provide system diagnostic information. (It also includes a copy of ThinkPwn.efi, be careful.) 
* [UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser) - UEFI Firmware Parser examines firmware 'blobs', mainly UEFI ones.
* [UEFITool](https://github.com/LongSoft/UEFITool) - UEFITool is a GUI program that parses firmware 'blobs', mainly UEFI ones.  In addition to the UEFITool Qt GUI tool, the UEFITool source project also includes a handful of non-GUI command line tools, including UEFIDump. UEFITool has two source trees to be aware of, master and new-engine.
* [Visual UEFI](https://github.com/ionescu007/VisualUefi) - Visual UEFI is a plugin for Visual Studio that lets Visual Studio users do UEFI EDK2 development without having to know the details of the EDK2 build process, which is not like the Visual Studio build process. 
* [zenfish IPMI tools](https://github.com/zenfish/ipmi) - IMPI security testing tools by Dan Farmer of [SATAN](http://www.fish2.com/satan/) fame.

## Documentation, Books and Training

* [Beyond BIOS](https://www.degruyter.com/view/product/484468) - Beyond BIOS: Developing with the Unified Extensible Firmware Interface, Third Edition. Book on UEFI by Intel and other UEFI Forum members. Originally published by Intel Press.
* [Darkreading Firmware Security Tips](https://www.darkreading.com/iot/5-tips-for-protecting-firmware-from-attacks/d/d-id/1325604) - This article, which has input from the Intel CHIPSEC team, gives basic high-level guidance for firmware security. Start with this, before digging into the NIST documents.
* [Firmware Security Blog](https://firmwaresecurity.com) - Source of firmware security and development news and information, with a focus on UEFI-centric platform firmware. (DISCLAIMER: One of the awesome-firmware authors, and PreOS employee is the Firmware Security blogger.)
* [Firmware Security Twitter List](https://twitter.com/JacobTorrey/lists/firmware-security) - Jacob Torrey hosts this list on Twitter, which contains many of the core firmware security researchers.
* [Hardware Security Training](https://hardwaresecurity.training/) - The Hardware Security Training company is a collection of multiple hardware/firmware security trainers.
* [Harnessing the UEFI Shell](https://www.degruyter.com/view/product/484477) - Harnessing the UEFI Shell: Moving the Platform Beyond DOS, Second Edition. Book on UEFI by Intel and other UEFI Forum members. Originally published by Intel Press.
* [Intel Security Training](https://github.com/advanced-threat-research/firmware-security-training) - training from the CHIPSEC team at Intel Advanced Threat Research (ATR) team of Intel Security. The documents are an AWESOME source of information about Intel hardware/firmware security threats, focusing on UEFI and related technologies.
* [IPMI Security Best Practices](http://www.fish2.com/ipmi/bp.pdf) - best practices for IPMI security from Dan Farmer. In need of an update. Most would apply to Redfish, or any OOB management technology.
* [Linux Foundation Workstation Security Policy](https://github.com/lfit/itpol) - The Linux Foundation has a collection of IT Policies, for Linux systems, it includes some firmware security guidance.
* [Linux on UEFI](http://www.rodsbooks.com/linux-uefi/) - Linux on UEFI Roderick W. Smith has an online book with information on UEFI and Linux, showing how to use multiple boot loaders.
* [Low Level PC Attack Papers](http://www.timeglider.com/timeline/5ca2daa6078caaf4) - an awesome timeline of hardware/firmware security research.
* [NIST]( https://csrc.nist.gov/) - firmware guidance documents. These are awesome. Start with [SP 800-193](https://csrc.nist.gov/CSRC/media/Publications/sp/800-193/draft/documents/sp800-193-draft.pdf)
  * [SP 800-147](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf) - an older document, aimed primarily at BIOS.
  * [SP 800-147b](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-147B.pdf) - an addition to [SP 800-147](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf) specifically for servers.
  * [SP 800-155](https://csrc.nist.gov/csrc/media/publications/sp/800-155/draft/documents/draft-sp800-155_dec2011.pdf) - note this standard is still in draft status, but it is still quite useable
  * [SP 800-193](https://csrc.nist.gov/CSRC/media/Publications/sp/800-193/draft/documents/sp800-193-draft.pdf) - note this standard is still in draft status, but quite useable and the most modern of all the documents. Start reading here.
* [NSA Common Criteria for PC BIOS Protection](https://www.niap-ccevs.org/Profile/Info.cfm?PPID=306&id=306) -  This 2013 Common Criteria Standard Protection Profile (PP) for PC firmware. Addresses the primary threat that an adversary will modify or replace the BIOS on a PC client device and compromise the PC client environment in a persistent way. There aren't any firmware solutions taht meet this profile, but reading the threat model is useful background.
* [One-Stop Shop for UEFI Links](https://github.com/uefitech/resources/blob/master/README.md) - One-Stop Shop for UEFI/BIOS Specifications/Tools Maintained by UEFI.Tech Community
* [Rootkits and Bootkits](https://nostarch.com/rootkits) - This is the only book on firmware security at the time, writen by firmware security experts.
