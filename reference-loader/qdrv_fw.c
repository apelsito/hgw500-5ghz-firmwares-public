/**
  Copyright (c) 2015 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 **/

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <crypto/sha2.h>
#include <om73_sram_backend.h>
#include "om73_fw_profiles.h"
#include <asm/io.h>
#include <asm/hardware.h>
#include <common/ruby_mem.h>
#include "qdrv_debug.h"
#include "qdrv_fw.h"
#include "qdrv_bld.h"

#define QDRV_FWINFO_VADDR	0xffff0000U
#define QDRV_FWINFO_TYPE_RELEASE	1U

struct qdrv_fwinfo {
	char magic[8];
	__le32 type;
	__le32 version;
} __packed;

/*
 * Releases newer than the public .62.1 tree add a synthetic PT_LOAD segment
 * at 0xffff0000.  It is metadata, not a load address.  Treating it as a real
 * AuC/MuC destination reaches the out-of-range address conversion path.  The
 * OEM .89 loader skips this segment and rejects a version mismatch before any
 * firmware payload is installed; preserve that fail-closed property here.
 */
static int qdrv_fw_check_info(const Elf32_Phdr *phdr, const char *data)
{
	const struct qdrv_fwinfo *info;
	u32 type;
	u32 version;

	if (phdr->p_vaddr != QDRV_FWINFO_VADDR)
		return 0;

	if (phdr->p_filesz < sizeof(*info)) {
		printk(KERN_ERR "qdrv: truncated FWINFO segment (%u bytes)\n",
			phdr->p_filesz);
		return -EINVAL;
	}

	info = (const struct qdrv_fwinfo *)data;
	if (memcmp(info->magic, "FWINFO", 6) != 0) {
		printk(KERN_ERR "qdrv: invalid FWINFO magic\n");
		return -EINVAL;
	}

	type = le32_to_cpu(info->type);
	version = le32_to_cpu(info->version);
	if (type != QDRV_FWINFO_TYPE_RELEASE) {
		printk(KERN_ERR "qdrv: unsupported FWINFO type 0x%x\n", type);
		return -EINVAL;
	}
	if (version != QDRV_BLD_VER) {
		printk(KERN_ERR
			"qdrv: firmware version 0x%x does not match host 0x%x\n",
			version, QDRV_BLD_VER);
		return -EPROTO;
	}

	return 1;
}

static int
auc_is_ccm_addr(unsigned long addr)
{
	return
		__in_mem_range(addr, TOPAZ_AUC_IMEM_ADDR, TOPAZ_AUC_IMEM_SIZE) ||
		__in_mem_range(addr, TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE);
}

static void
auc_write_ccm_uint8(void *dst, uint8_t val)
{
	unsigned long addr = (unsigned long)dst;
	unsigned long addr_align = addr & ~0x3;
	unsigned long val_shift = (addr & 0x3) * BITS_PER_BYTE;
	unsigned mem_val = readl(addr_align);

	mem_val = mem_val & ~(0xFF << val_shift);
	mem_val = mem_val | (val << val_shift);

	writel(mem_val, addr_align);
}

static void auc_memzero_ccm(void *dst, unsigned long size)
{
	char *dst_c = (char *)dst;

	while (size > 0) {
		auc_write_ccm_uint8(dst_c, 0);
		--size;
		++dst_c;
	}
}

static void auc_memcpy_ccm(void *dst, const void *src, unsigned long size)
{
	char *dst_c = (char *)dst;
	const char *src_c = (const char *)src;

	while (size > 0) {
		auc_write_ccm_uint8(dst_c, readb(src_c));
		--size;
		++dst_c;
		++src_c;
	}
}

void qdrv_fw_auc_memzero(void *dst, unsigned long size, unsigned long dst_phys_addr)
{
	if (auc_is_ccm_addr(dst_phys_addr)) {
		auc_memzero_ccm(dst, size);
	} else {
		memset(dst, 0, size);
	}
}

static
void qdrv_fw_auc_memcpy(void *dst, const void *src, unsigned long size, unsigned long dst_phys_addr)
{
	if (auc_is_ccm_addr(dst_phys_addr)) {
		auc_memcpy_ccm(dst, src, size);
	} else {
		memcpy(dst, src, size);
	}
}

unsigned long
qdrv_fw_auc_to_host_addr(unsigned long auc_addr)
{
	void *ret = bus_to_virt(auc_addr);
	if (RUBY_BAD_VIRT_ADDR == ret) {
		panic("Converting out of range AuC address 0x%lx to host address\n", auc_addr);
	}
	return virt_to_phys(ret);
}

static unsigned long
qdrv_fw_muc_to_host_addr(unsigned long muc_addr)
{
	void *ret = (void*)muc_to_lhost(muc_addr);
	if (RUBY_BAD_VIRT_ADDR == ret) {
		panic("Converting out of range MuC address 0x%lx to host address\n", muc_addr);
	}
	return virt_to_phys(ret);
}

static unsigned long
qdrv_fw_dsp_to_host_addr(unsigned long dsp_addr)
{
	void *ret = bus_to_virt(dsp_addr);
	if (RUBY_BAD_VIRT_ADDR == ret) {
		panic("Converting out of range DSP address 0x%lx to host address\n", dsp_addr);
	}
	return virt_to_phys(ret);
}

enum qdrv_fw_cpu {
	qdrv_fw_muc,
	qdrv_fw_auc,
	qdrv_fw_dsp
};

/* The shipping carriers pack their program table directly after Ehdr and
 * concatenate payloads. BSS-only p_offset may refer to an earlier payload;
 * no data is read for those entries. Preserve that format, but validate every
 * byte/range before the first map/copy or publishing a start address. */
static int qdrv_fw_physical_range(unsigned long address, u32 bytes,
                                 enum qdrv_fw_cpu cpu)
{
    unsigned long end;
    if (!bytes || address > U32_MAX - (bytes - 1))
        return -ERANGE;
    end = address + bytes - 1;
    if (__in_mem_range(address, RUBY_SRAM_BEGIN, RUBY_SRAM_SIZE) &&
        __in_mem_range(end, RUBY_SRAM_BEGIN, RUBY_SRAM_SIZE))
        return 0;
    if (__in_mem_range(address, RUBY_DRAM_BEGIN, RUBY_MAX_DRAM_SIZE) &&
        __in_mem_range(end, RUBY_DRAM_BEGIN, RUBY_MAX_DRAM_SIZE))
        return 0;
    if (cpu == qdrv_fw_auc &&
        ((__in_mem_range(address, TOPAZ_AUC_IMEM_ADDR, TOPAZ_AUC_IMEM_SIZE) &&
          __in_mem_range(end, TOPAZ_AUC_IMEM_ADDR, TOPAZ_AUC_IMEM_SIZE)) ||
         (__in_mem_range(address, TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE) &&
          __in_mem_range(end, TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE))))
        return 0;
    return -ERANGE;
}

static int qdrv_fw_segment_address(const Elf32_Phdr *phdr,
                                   enum qdrv_fw_cpu cpu,
                                   unsigned long *address)
{
    unsigned long source;
    void *host;
    if (cpu == qdrv_fw_dsp && phdr->p_vaddr >= RUBY_DSP_XYMEM_BEGIN &&
        phdr->p_vaddr <= RUBY_DSP_XYMEM_END) {
        if (!phdr->p_memsz || phdr->p_memsz - 1 > RUBY_DSP_XYMEM_END - phdr->p_vaddr)
            return -ERANGE;
        return 1; /* Retain the DSP X/Y skip; this loader does not write it. */
    }
    if (cpu < qdrv_fw_muc || cpu > qdrv_fw_dsp)
        return -EINVAL;
    source = cpu == qdrv_fw_dsp ? phdr->p_vaddr :
             (phdr->p_paddr ? phdr->p_paddr : phdr->p_vaddr);
    host = cpu == qdrv_fw_muc ? (void *)muc_to_lhost(source) : bus_to_virt(source);
    if (host == RUBY_BAD_VIRT_ADDR)
        return -ERANGE;
    *address = virt_to_phys(host);
    return qdrv_fw_physical_range(*address, phdr->p_memsz, cpu);
}

static int qdrv_fw_preflight(const char *data, size_t size,
                             enum qdrv_fw_cpu cpu, Elf32_Ehdr *header)
{
    Elf32_Phdr phdr;
    size_t cursor, table_bytes;
    unsigned long address;
    u32 i;
    int ret;
    if (!data || !header || size < sizeof(*header) ||
        cpu < qdrv_fw_muc || cpu > qdrv_fw_dsp)
        return -EINVAL;
    memcpy(header, data, sizeof(*header));
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) ||
        header->e_ident[EI_CLASS] != ELFCLASS32 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_ident[EI_VERSION] != EV_CURRENT ||
        header->e_version != EV_CURRENT || header->e_type != ET_EXEC ||
        header->e_machine != EM_ARCOMPACT ||
        header->e_ehsize != sizeof(*header) ||
        header->e_phoff != sizeof(*header) ||
        header->e_phentsize != sizeof(phdr) || !header->e_phnum)
        return -ENOEXEC;
    table_bytes = (size_t)header->e_phnum * sizeof(phdr);
    if (table_bytes > size - sizeof(*header))
        return -EINVAL;
    cursor = sizeof(*header) + table_bytes;
    for (i = 0; i < header->e_phnum; i++) {
        memcpy(&phdr, data + sizeof(*header) + i * sizeof(phdr), sizeof(phdr));
        if (phdr.p_type != PT_LOAD || phdr.p_filesz > phdr.p_memsz ||
            phdr.p_filesz > size - cursor || phdr.p_offset > size ||
            (phdr.p_filesz && phdr.p_offset != cursor))
            return -EINVAL;
        ret = qdrv_fw_check_info(&phdr, data + cursor);
        if (ret < 0)
            return ret;
        if (!ret) {
            ret = qdrv_fw_segment_address(&phdr, cpu, &address);
            if (ret < 0)
                return ret;
        }
        cursor += phdr.p_filesz;
    }
    /* Entry is processor-relative, while p_paddr may hold a load copy address.
     * Validate it independently without demanding it match the load-copy VA. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_vaddr = header->e_entry;
    phdr.p_memsz = 1;
    ret = qdrv_fw_segment_address(&phdr, cpu, &address);
    return ret ? (ret < 0 ? ret : -ERANGE) : 0;
}


/* Identity and the full structural/address plan are checked while the pool's
 * lifecycle lease is held. Thus acquire/close cannot change the arena between
 * exclusion of destinations and the final segment write. Metadata and DSP X/Y
 * skips retain their OEM meaning. This is not proof of indirect writer bounds. */
static int qdrv_fw_writer_preflight(const char *data, size_t size,
                                   enum qdrv_fw_cpu cpu,
                                   const struct om73_sram_writer_token *writer)
{
    Elf32_Ehdr header;
    Elf32_Phdr phdr;
    size_t cursor;
    unsigned long address;
    u8 digest[SHA256_DIGEST_SIZE];
    u32 i;
    int ret;
    if (!data || cpu < qdrv_fw_muc || cpu > qdrv_fw_dsp ||
        size != om73_fw_profiles[cpu].bytes)
        return -EKEYREJECTED;
    sha256((const u8 *)data, size, digest);
    if (memcmp(digest, om73_fw_profiles[cpu].sha256, sizeof(digest)))
        return -EKEYREJECTED;
    ret = qdrv_fw_preflight(data, size, cpu, &header);
    if (ret)
        return ret;
    cursor = sizeof(header) + (size_t)header.e_phnum * sizeof(phdr);
    for (i = 0; i < header.e_phnum; i++) {
        memcpy(&phdr, data + sizeof(header) + i * sizeof(phdr), sizeof(phdr));
        ret = qdrv_fw_check_info(&phdr, data + cursor);
        if (!ret) {
            ret = qdrv_fw_segment_address(&phdr, cpu, &address);
            if (!ret) {
                ret = om73_sram_writer_check(writer, address, phdr.p_memsz);
                if (ret)
                    return ret;
            } else if (ret < 0) {
                return ret;
            }
        }
        cursor += phdr.p_filesz;
    }
    return 0;
}

static int qdrv_fw_install_segment(const Elf32_Phdr *phdr,
		const char *data,
		enum qdrv_fw_cpu cpu)
{
	uint8_t *vaddr;
	unsigned long paddr;

	int ret = qdrv_fw_segment_address(phdr, cpu, &paddr);
	if (ret)
		return ret > 0 ? 0 : ret;

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_TRACE, "ELF header p_vaddr=%p p_paddr=%p, "
				 "remapping to 0x%lx filesz %d memsz %d\n",
			(void*)phdr->p_vaddr, (void*)phdr->p_paddr,
			paddr, phdr->p_filesz, phdr->p_memsz);

	vaddr = ioremap_nocache(paddr, phdr->p_memsz);
	if (!vaddr)
		return -ENOMEM;

	/* Copy data and clear BSS */
	if (cpu == qdrv_fw_auc) {
		qdrv_fw_auc_memcpy(vaddr, data, phdr->p_filesz, paddr);
		qdrv_fw_auc_memzero(vaddr + phdr->p_filesz, phdr->p_memsz - phdr->p_filesz, paddr);
	} else {
		memcpy(vaddr, data, phdr->p_filesz);
		memset(vaddr + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
	}

	iounmap(vaddr);
	return 0;
}

static int qdrv_fw_install(const char *data, size_t size,
                           uint32_t *start_addr, enum qdrv_fw_cpu cpu)
{
	Elf32_Ehdr header;
	Elf32_Phdr phdr;
	size_t cursor;
	u32 i;
	int ret;

	if (!start_addr)
		return -EINVAL;
	ret = qdrv_fw_preflight(data, size, cpu, &header);
	if (ret)
		return ret;
	cursor = sizeof(header) + (size_t)header.e_phnum * sizeof(phdr);
	for (i = 0; i < header.e_phnum; i++) {
		memcpy(&phdr, data + sizeof(header) + i * sizeof(phdr), sizeof(phdr));
		ret = qdrv_fw_check_info(&phdr, data + cursor);
		if (!ret) {
			ret = qdrv_fw_install_segment(&phdr, data + cursor, cpu);
			if (ret)
				return ret;
		}
		cursor += phdr.p_filesz;
	}
	/* Publish entry only after every segment was successfully installed. */
	*start_addr = header.e_entry;
	return header.e_phnum;
}

static const char *qdrv_fw_cpu_str[] = {
		[qdrv_fw_muc] = "MuC",
		[qdrv_fw_auc] = "AuC",
		[qdrv_fw_dsp] = "DSP"
};

static
int qdrv_fw_load_prepared(struct device *dev,
		char *firmware,
		uint32_t *start_addr,
		enum qdrv_fw_cpu cpu, qdrv_fw_prepare_fn prepare, void *context)
{
	const struct firmware *fw;
	struct om73_sram_writer_token writer;
	u32 loaded_entry;
	int ret, end_ret;

	if (!start_addr || !firmware || cpu < qdrv_fw_muc || cpu > qdrv_fw_dsp)
		return -EINVAL;
	ret = request_firmware(&fw, firmware, dev);
	if (ret)
		return ret;
	ret = om73_sram_writer_begin(cpu, &writer);
	if (ret)
		goto release;
	ret = qdrv_fw_writer_preflight((const char *)fw->data, fw->size, cpu, &writer);
	if (!ret && prepare) {
		ret = prepare(&writer, context);
		if (ret > 0)
			ret = -EPROTO;
	}
	if (!ret)
		ret = qdrv_fw_install((const char *)fw->data, fw->size, &loaded_entry, cpu);
	end_ret = om73_sram_writer_end(&writer);
	if (ret > 0 && end_ret)
		ret = end_ret;
	if (ret > 0)
		*start_addr = loaded_entry;
release:
	release_firmware(fw);
	return ret;
}

static int qdrv_fw_load(struct device *dev, char *firmware, uint32_t *start,
                         enum qdrv_fw_cpu cpu)
{
    return qdrv_fw_load_prepared(dev, firmware, start, cpu, NULL, NULL);
}

int qdrv_fw_load_auc_prepared(struct device *dev, char *firmware, uint32_t *start,
                             qdrv_fw_prepare_fn prepare, void *context)
{
    if (!prepare)
        return -EINVAL;
    return qdrv_fw_load_prepared(dev, firmware, start, qdrv_fw_auc, prepare, context);
}

int qdrv_fw_load_muc(struct device *dev,
		char *firmware,
		uint32_t *start_addr)
{
	return qdrv_fw_load(dev, firmware, start_addr, qdrv_fw_muc);
}

int qdrv_fw_load_auc(struct device *dev,
		char *firmware,
		uint32_t *start_addr)
{
	return qdrv_fw_load(dev, firmware, start_addr, qdrv_fw_auc);
}

int qdrv_fw_load_dsp(struct device *dev,
		char *firmware,
		uint32_t *start_addr)
{
	return qdrv_fw_load(dev, firmware, start_addr, qdrv_fw_dsp);
}
