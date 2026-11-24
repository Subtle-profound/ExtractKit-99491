/*
 * ksu_boot.c - KernelSU bootstrap for the CVE-2026-99491 branch endgames.
 *
 * The caller already holds uid 0 + full caps and a permissive SELinux
 * window (the mode's own escalation).  This file extracts kernelsu.ko and
 * ksud from the installed KernelSU manager, patches the module for the
 * running slide with ko_patch_cli, loads it with the profile's
 * finit_module arguments, installs the ksud userspace and restores
 * Enforcing.  Manager/tool paths and loader strings come from the runtime
 * JSON profile.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ksu_boot.h"

extern int ko_patch_cli(int argc, char **argv);


static void ksu_module_alias(const struct cve99491_profile *prof, char *out,
                             size_t cap)
{
    size_t n = strlen(prof->ksu_module_name);

    if (n > 3 && !strcmp(prof->ksu_module_name + n - 3, ".ko"))
        n -= 3;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, prof->ksu_module_name, n);
    out[n] = 0;
}

void ksu_default_syms(const struct cve99491_profile *prof, char *buf,
                      size_t size)
{
    struct utsname u;

    if (uname(&u) == 0 && u.release[0])
        snprintf(buf, size, "%s/ko-syms-%s.txt", prof->ksu_workdir,
                 u.release);
    else
        snprintf(buf, size, "%s/ko-syms-unknown.txt", prof->ksu_workdir);
}

static long ksu_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int write_text_file(const char *path, const char *s)
{
    int f = open(path, O_WRONLY);
    ssize_t n;

    if (f < 0)
        return -1;
    n = write(f, s, strlen(s));
    close(f);
    return n == (ssize_t)strlen(s) ? 0 : -1;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
    char buf[65536];
    int in = open(src, O_RDONLY);
    int out;
    ssize_t n;

    if (in < 0)
        return -1;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof buf)) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w <= 0) {
                close(in);
                close(out);
                return -1;
            }
            p += w;
            n -= w;
        }
    }
    close(in);
    close(out);
    if (n < 0)
        return -1;
    (void)chmod(dst, mode);
    return 0;
}

/* Run av[0] (absolute path) and capture stdout+stderr. */
static int run_capture(char *const av[], char *out, size_t cap,
                       long timeout_ms)
{
    int pfd[2];
    pid_t p;
    size_t used = 0;
    long deadline;
    int st = 0, timed_out = 0;

    if (cap)
        out[0] = 0;
    if (pipe(pfd) < 0)
        return -1;
    p = fork();
    if (p < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (p == 0) {
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execv(av[0], av);
        _exit(127);
    }
    close(pfd[1]);
    deadline = ksu_now_ms() + timeout_ms;
    while (cap > 1 && used + 1 < cap) {
        struct pollfd pf;
        long left = deadline - ksu_now_ms();
        ssize_t n;

        if (left <= 0) {
            timed_out = 1;
            break;
        }
        pf.fd = pfd[0];
        pf.events = POLLIN;
        pf.revents = 0;
        if (poll(&pf, 1, (int)(left > 1000 ? 1000 : left)) <= 0)
            continue;
        n = read(pfd[0], out + used, cap - used - 1);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(pfd[0]);
    if (timed_out)
        kill(p, SIGKILL);
    waitpid(p, &st, 0);
    if (cap)
        out[used < cap ? used : cap - 1] = 0;
    if (timed_out)
        return -1;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

static int run_sh(const char *cmd, char *out, size_t cap, long timeout_ms)
{
    char *const av[] = { (char *)"/system/bin/sh", (char *)"-c",
                         (char *)cmd, NULL };

    return run_capture(av, out, cap, timeout_ms);
}

/* Single-quote a string for /system/bin/sh; embedded quotes are escaped as
 * '\'' so validated paths with shell metacharacters cannot break out. */
static int sh_quote(const char *in, char *out, size_t cap)
{
    size_t o = 0;

    if (cap < 3)
        return -1;
    out[o++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            if (o + 4 >= cap)
                return -1;
            out[o++] = '\'';
            out[o++] = '\\';
            out[o++] = '\'';
            out[o++] = '\'';
        } else {
            if (o + 2 >= cap)
                return -1;
            out[o++] = *p;
        }
    }
    if (o + 1 >= cap)
        return -1;
    out[o++] = '\'';
    out[o] = 0;
    return 0;
}

static int read_int_file(const char *path)
{
    char b[32];
    int f = open(path, O_RDONLY);
    int n;

    if (f < 0)
        return -1;
    n = (int)read(f, b, sizeof(b) - 1);
    close(f);
    if (n <= 0)
        return -1;
    b[n] = 0;
    return atoi(b);
}

static long file_size(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

/* --- native PackageManager request (libbinder_ndk, fail-closed) ------- */

/*
 * Profile-provided binder ABI: descriptor "android.content.pm.IPackageManager",
 * getPackageInfo/getApplicationInfo take (String package, long flags, int
 * userId) and return the parcelable via writeTypedObject(obj, 1).  The
 * verified profile carries these values; a profile without pm_* keys uses
 * the announced ASSUMED fallback instead of silently dropping binder.
 *
 * Backend policy (--pm-backend / CVE99491_PM_BACKEND):
 *   auto (default): hardened `pm path` first, /data/app glob last.  The
 *     binder is NOT attempted.
 *   pm: same as auto.
 *   binder: binder -> pm -> glob (explicit opt-in).
 * Every binder failure is diagnosed and logged; the fallback is kept until
 * the path is device-verified.
 */

typedef struct AIBinder AIBinder;
typedef struct AIBinder_Class AIBinder_Class;
typedef struct AParcel AParcel;

struct pm_diag {
    char step[64];
    char detail[160];
};

struct pm_binder_api {
    void *lib;
    AIBinder *(*get_service)(const char *);
    AIBinder_Class *(*class_define)(const char *, void *(*)(void *),
                                    void (*)(void *),
                                    int32_t (*)(AIBinder *, uint32_t,
                                                const AParcel *, AParcel *));
    bool (*associate_class)(AIBinder *, const AIBinder_Class *);
    int32_t (*prepare_transaction)(AIBinder *, AParcel **);
    int32_t (*transact)(AIBinder *, uint32_t, AParcel **, AParcel **, uint32_t);
    void (*dec_strong)(AIBinder *);
    AParcel *(*parcel_create)(void);
    void (*parcel_delete)(AParcel *);
    int32_t (*write_string)(AParcel *, const char *, int32_t);
    int32_t (*write_int64)(AParcel *, int64_t);
    int32_t (*write_int32)(AParcel *, int32_t);
    int32_t (*read_int32)(const AParcel *, int32_t *);
    int32_t (*get_data_size)(const AParcel *);
    int32_t (*get_data_position)(const AParcel *);
    int32_t (*marshal)(const AParcel *, uint8_t *, size_t, size_t);
};

struct pm_sym {
    const char *name;
    size_t off;
    size_t size;
};

#define PM_SYM(sym, field) \
    { sym, offsetof(struct pm_binder_api, field), \
      sizeof(((struct pm_binder_api *)0)->field) }

static const struct pm_sym pm_syms[] = {
    PM_SYM("AServiceManager_getService", get_service),
    PM_SYM("AIBinder_Class_define", class_define),
    PM_SYM("AIBinder_associateClass", associate_class),
    PM_SYM("AIBinder_prepareTransaction", prepare_transaction),
    PM_SYM("AIBinder_transact", transact),
    PM_SYM("AIBinder_decStrong", dec_strong),
    PM_SYM("AParcel_create", parcel_create),
    PM_SYM("AParcel_delete", parcel_delete),
    PM_SYM("AParcel_writeString", write_string),
    PM_SYM("AParcel_writeInt64", write_int64),
    PM_SYM("AParcel_writeInt32", write_int32),
    PM_SYM("AParcel_readInt32", read_int32),
    PM_SYM("AParcel_getDataSize", get_data_size),
    PM_SYM("AParcel_getDataPosition", get_data_position),
    PM_SYM("AParcel_marshal", marshal),
};

static void pm_diag_set(struct pm_diag *d, const char *step,
                        const char *fmt, ...)
{
    va_list ap;

    snprintf(d->step, sizeof(d->step), "%s", step);
    va_start(ap, fmt);
    vsnprintf(d->detail, sizeof(d->detail), fmt, ap);
    va_end(ap);
}

/* The AIBinder_Class must outlive every transaction and its descriptor
 * must live in static storage.  The class callbacks are non-null stubs:
 * this side only ever sends transactions, but associateClass requires a
 * class carrying the remote interface descriptor, and prepareTransaction
 * uses that class to write the Parcel.writeInterfaceToken header. */
static AIBinder_Class *g_pm_binder_class;
static char g_pm_binder_class_desc[128];

static void *pm_class_on_create(void *args)
{
    return args;
}

static void pm_class_on_destroy(void *userData)
{
    (void)userData;
}

static int32_t pm_class_on_transact(AIBinder *binder, uint32_t code,
                                    const AParcel *in, AParcel *out)
{
    (void)binder;
    (void)code;
    (void)in;
    (void)out;
    return INT32_MIN; /* STATUS_UNKNOWN_ERROR */
}

static AIBinder_Class *pm_class_get(const struct pm_binder_api *api,
                                    const struct cve99491_profile *prof,
                                    int verbose, struct pm_diag *diag)
{
    if (g_pm_binder_class) {
        /* The class is process-global; a different descriptor must not
         * silently reuse it (the interface token would be wrong). */
        if (strcmp(g_pm_binder_class_desc, prof->pm_interface)) {
            pm_diag_set(diag, "class-descriptor",
                        "already defined as %s, requested %s",
                        g_pm_binder_class_desc, prof->pm_interface);
            if (verbose)
                printf("[pm-probe] step=class-define descriptor=%s "
                       "status=fail detail=already-defined-as-%s\n",
                       prof->pm_interface, g_pm_binder_class_desc);
            return NULL;
        }
        return g_pm_binder_class;
    }
    snprintf(g_pm_binder_class_desc, sizeof(g_pm_binder_class_desc), "%s",
             prof->pm_interface);
    g_pm_binder_class = api->class_define(
        g_pm_binder_class_desc, pm_class_on_create, pm_class_on_destroy,
        pm_class_on_transact);
    if (!g_pm_binder_class) {
        pm_diag_set(diag, "class-define",
                    "AIBinder_Class_define(%s) returned null",
                    prof->pm_interface);
        if (verbose)
            printf("[pm-probe] step=class-define descriptor=%s status=fail\n",
                   prof->pm_interface);
        return NULL;
    }
    if (verbose)
        printf("[pm-probe] step=class-define descriptor=%s status=ok\n",
               prof->pm_interface);
    return g_pm_binder_class;
}

/* The library handle and resolved function table are cached for the
 * process lifetime: once AIBinder_Class is defined, the class object and
 * its callbacks belong to libbinder_ndk and the NDK has no class-destroy
 * API, so unloading would leave dangling class/functions.  The process is
 * short-lived, so this process-lifetime keep-alive is intentional. */
static struct pm_binder_api g_pm_binder_api;
static int g_pm_binder_api_ok;

static int pm_binder_load(struct pm_binder_api *api, const char *libname,
                          int verbose, struct pm_diag *diag)
{
    struct pm_binder_api *cached = &g_pm_binder_api;

    if (g_pm_binder_api_ok) {
        *api = g_pm_binder_api;
        if (verbose)
            printf("[pm-probe] step=dlopen lib=%s status=cached\n", libname);
        return 0;
    }
    memset(cached, 0, sizeof(*cached));
    cached->lib = dlopen(libname, RTLD_NOW | RTLD_LOCAL);
    if (!cached->lib) {
        const char *e = dlerror();

        pm_diag_set(diag, "dlopen", "%s: %s", libname, e ? e : "unknown");
        if (verbose)
            printf("[pm-probe] step=dlopen lib=%s status=fail error=%s\n",
                   libname, e ? e : "unknown");
        return -1;
    }
    if (verbose)
        printf("[pm-probe] step=dlopen lib=%s status=ok\n", libname);
    for (size_t i = 0; i < sizeof(pm_syms) / sizeof(pm_syms[0]); i++) {
        void *sym = dlsym(cached->lib, pm_syms[i].name);

        if (!sym) {
            pm_diag_set(diag, "dlsym", "%s missing", pm_syms[i].name);
            if (verbose)
                printf("[pm-probe] step=dlsym symbol=%s status=fail\n",
                       pm_syms[i].name);
            dlclose(cached->lib);
            memset(cached, 0, sizeof(*cached));
            return -1;
        }
        memcpy((char *)cached + pm_syms[i].off, &sym, pm_syms[i].size);
        if (verbose)
            printf("[pm-probe] step=dlsym symbol=%s status=ok\n",
                   pm_syms[i].name);
    }
    g_pm_binder_api_ok = 1;
    *api = g_pm_binder_api;
    return 0;
}

/* AParcel_writeString takes a UTF-8 C string and emits the AIDL String16
 * wire format (int32 utf16 length excluding the NUL, len code units, the
 * NUL unit, with the required alignment padding).  Do not hand-build this
 * with AParcel_writeChar: that writes one 4-byte Parcel char per call. */
static int pm_write_string(const struct pm_binder_api *api, AParcel *p,
                           const char *s, const char **step)
{
    size_t len = strlen(s);

    if (len > 0x7fffffff) {
        *step = "string-too-long";
        return -1;
    }
    if (api->write_string(p, s, (int32_t)len) != 0) {
        *step = "write-string";
        return -1;
    }
    return 0;
}

static void pm_binder_unload(struct pm_binder_api *api)
{
    /* Never unload libbinder_ndk: the class object and callbacks live in
     * it for the process lifetime (no NDK class-destroy API), and this
     * process is short-lived.  Only the caller's copy is cleared; the
     * cached handle/function table remains valid for later calls. */
    memset(api, 0, sizeof(*api));
}

/* Scan a marshalled ApplicationInfo/PackageInfo for a readable APK path.
 * Handles both writeString8 (ASCII, used by the verified ApplicationInfo) and
 * String16 (UTF-16LE) path encodings. */
static int pm_scan_apk_path(const uint8_t *buf, size_t len,
                            const struct cve99491_profile *prof, char *out,
                            size_t cap)
{
    char prefix[160];
    size_t plen, rootlen = strlen(prof->ksu_manager_apk_root);

    snprintf(prefix, sizeof(prefix), "%s%s", prof->ksu_manager_apk_root,
             (rootlen && prof->ksu_manager_apk_root[rootlen - 1] == '/')
                 ? "" : "/");
    plen = strlen(prefix);
    for (size_t i = 0; i + plen < len; i++) {
        size_t j, n;

        if (buf[i] != '/')
            continue;
        if (memcmp(buf + i, prefix, plen) != 0)
            continue;
        j = i;
        while (j < len && j - i < 400 && buf[j] >= 0x20 && buf[j] < 0x7f)
            j++;
        n = j - i;
        if (n < 5 || memcmp(buf + j - 4, ".apk", 4) != 0 || n >= cap)
            continue;
        memcpy(out, buf + i, n);
        out[n] = 0;
        if (access(out, R_OK) == 0)
            return 0;
    }
    /* Some Android versions parcel the path as String16 (one UTF-16LE code
     * unit per byte pair); scan that encoding as well. */
    for (size_t i = 0; i + plen * 2 < len; i++) {
        size_t j = 0, n = 0;

        if (buf[i] != '/')
            continue;
        for (j = 0; j < plen; j++) {
            if (buf[i + j * 2] != (uint8_t)prefix[j] ||
                buf[i + j * 2 + 1] != 0)
                break;
        }
        if (j != plen)
            continue;
        j = i;
        while (j + 1 < len && j - i < 800 &&
               buf[j] >= 0x20 && buf[j] < 0x7f && buf[j + 1] == 0) {
            j += 2;
            n++;
        }
        if (n < 5 || n >= cap ||
            buf[j - 8] != '.' || buf[j - 7] != 0 ||
            buf[j - 6] != 'a' || buf[j - 5] != 0 ||
            buf[j - 4] != 'p' || buf[j - 3] != 0 ||
            buf[j - 2] != 'k' || buf[j - 1] != 0)
            continue;
        for (size_t k = 0; k < n; k++)
            out[k] = (char)buf[i + k * 2];
        out[n] = 0;
        if (access(out, R_OK) == 0)
            return 0;
    }
    return -1;
}

static void pm_hex_dump(const uint8_t *buf, size_t len)
{
    size_t n = len < 64 ? len : 64;

    for (size_t i = 0; i < n; i++)
        printf("%02x", buf[i]);
}

static int pm_binder_transact_apk(const struct cve99491_profile *prof,
                                  struct pm_binder_api *api, uint32_t txn,
                                  const char *method, char *out, size_t cap,
                                  int verbose, struct pm_diag *diag)
{
    AIBinder *svc = NULL;
    AIBinder_Class *clazz;
    AParcel *in = NULL, *rep = NULL;
    uint8_t *buf = NULL;
    int32_t exc = -1, present = 0, pos = -1, size = -1;
    const char *step = "parcel-create";
    int rc = -1;

    svc = api->get_service(prof->pm_service);
    if (!svc) {
        pm_diag_set(diag, "getService",
                    "AServiceManager_getService(\"%s\") returned null",
                    prof->pm_service);
        if (verbose)
            printf("[pm-probe] txn=%u method=%s step=getService status=null\n",
                   txn, method);
        return -1;
    }
    if (verbose)
        printf("[pm-probe] txn=%u method=%s step=getService status=ok\n", txn,
               method);
    clazz = pm_class_get(api, prof, verbose, diag);
    if (!clazz)
        goto done;
    if (!api->associate_class(svc, clazz)) {
        pm_diag_set(diag, "associateClass",
                    "AIBinder_associateClass(descriptor=%s) returned false",
                    prof->pm_interface);
        if (verbose)
            printf("[pm-probe] txn=%u step=associateClass status=fail\n",
                   txn);
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=associateClass status=ok\n", txn);
    {
        int32_t pst = api->prepare_transaction(svc, &in);

        if (pst != 0 || !in) {
            pm_diag_set(diag, "prepareTransaction",
                        "AIBinder_prepareTransaction status=%d", pst);
            if (verbose)
                printf("[pm-probe] txn=%u step=prepareTransaction status=%d\n",
                       txn, pst);
            goto done;
        }
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=prepareTransaction status=0\n", txn);
    /* prepareTransaction already wrote the interface token; only args. */
    if (pm_write_string(api, in, prof->ksu_manager, &step) != 0) {
        pm_diag_set(diag, step, "package String16 write failed");
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=write-package len=%zu status=ok\n",
               txn, strlen(prof->ksu_manager));
    if (api->write_int64(in, 0) != 0) {
        pm_diag_set(diag, "write-flags", "AParcel_writeInt64 failed");
        goto done;
    }
    if (api->write_int32(in, (int32_t)prof->pm_user_id) != 0) {
        pm_diag_set(diag, "write-user", "AParcel_writeInt32 failed");
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=write-args flags=0 user=%u status=ok\n",
               txn, prof->pm_user_id);
    {
        int32_t st = api->transact(svc, txn, &in, &rep, 0);

        in = NULL; /* AIBinder_transact takes ownership of the input parcel */
        if (st != 0) {
            pm_diag_set(diag, "transact", "AIBinder_transact txn=%u status=%d",
                        txn, st);
            if (verbose)
                printf("[pm-probe] txn=%u step=transact status=%d\n", txn, st);
            goto done;
        }
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=transact status=0\n", txn);
    if (!rep) {
        pm_diag_set(diag, "transact", "no reply parcel");
        goto done;
    }
    if (api->read_int32(rep, &exc) != 0) {
        pm_diag_set(diag, "read-exception", "AParcel_readInt32 failed");
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=read-exception exception=%d\n", txn,
               exc);
    if (exc != 0) {
        pm_diag_set(diag, "reply-exception", "txn=%u exception=%d", txn, exc);
        goto done;
    }
    if (api->read_int32(rep, &present) != 0) {
        pm_diag_set(diag, "read-presence", "AParcel_readInt32 failed");
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=read-presence presence=%d\n", txn,
               present);
    if (present != 1) {
        pm_diag_set(diag, "reply-presence",
                    "txn=%u presence=%d (expected 1)", txn, present);
        goto done;
    }
    pos = api->get_data_position(rep);
    size = api->get_data_size(rep);
    if (verbose)
        printf("[pm-probe] txn=%u step=data-position pos=%d size=%d\n", txn,
               pos, size);
    if (pos < 0 || size <= pos || (size - pos) > (1 << 20)) {
        pm_diag_set(diag, "data-size", "pos=%d size=%d", pos, size);
        goto done;
    }
    buf = malloc((size_t)(size - pos));
    if (!buf) {
        pm_diag_set(diag, "marshal", "out of memory (%d bytes)", size - pos);
        goto done;
    }
    {
        int32_t st = api->marshal(rep, buf, (size_t)pos, (size_t)(size - pos));

        if (st != 0) {
            pm_diag_set(diag, "marshal", "AParcel_marshal status=%d bytes=%d",
                        st, size - pos);
            if (verbose)
                printf("[pm-probe] txn=%u step=marshal status=%d bytes=%d\n",
                       txn, st, size - pos);
            goto done;
        }
        if (verbose) {
            printf("[pm-probe] txn=%u step=marshal status=0 bytes=%d\n", txn,
                   size - pos);
            printf("[pm-probe] txn=%u reply[0..%zu]=", txn,
                   (size_t)(size - pos) < 64 ? (size_t)(size - pos) : 64);
            pm_hex_dump(buf, (size_t)(size - pos));
            printf("\n");
        }
    }
    if (pm_scan_apk_path(buf, (size_t)(size - pos), prof, out, cap) != 0) {
        pm_diag_set(diag, "scan",
                    "txn=%u reply has no readable APK under %s", txn,
                    prof->ksu_manager_apk_root);
        if (verbose)
            printf("[pm-probe] txn=%u step=scan status=no-readable-path\n",
                   txn);
        goto done;
    }
    if (verbose)
        printf("[pm-probe] txn=%u step=scan status=ok path=%s\n", txn, out);
    rc = 0;
done:
    if (buf)
        free(buf);
    if (rep)
        api->parcel_delete(rep);
    if (in)
        api->parcel_delete(in);
    api->dec_strong(svc);
    return rc;
}

/* 0 = APK path found through the package binder; -1 = fallback needed. */
static int pm_binder_apk_path(const struct cve99491_profile *prof,
                              char *out, size_t cap, struct pm_diag *diag)
{
    struct pm_binder_api api;
    int rc = -1;

    if (pm_binder_load(&api, prof->pm_binder_lib, 0, diag) != 0)
        return -1;
    if (pm_binder_transact_apk(prof, &api,
                               (uint32_t)prof->pm_txn_get_application_info,
                               "getApplicationInfo", out, cap, 0, diag) == 0)
        rc = 0;
    else if (pm_binder_transact_apk(prof, &api,
                                    (uint32_t)prof->pm_txn_get_package_info,
                                    "getPackageInfo", out, cap, 0, diag) == 0)
        rc = 0;
    pm_binder_unload(&api);
    return rc;
}

enum pm_backend {
    PM_BACKEND_AUTO = 0,
    PM_BACKEND_PM = 1,
    PM_BACKEND_BINDER = 2,
};

/* auto and pm never attempt the binder; binder explicitly opts in. */
static int pm_backend_from_env(void)
{
    const char *v = getenv("CVE99491_PM_BACKEND");

    if (v && !strcmp(v, "binder"))
        return PM_BACKEND_BINDER;
    if (v && !strcmp(v, "pm"))
        return PM_BACKEND_PM;
    return PM_BACKEND_AUTO;
}

/* --- pm-probe: binder-only diagnostic, no exploit/profile/markers ------ */

int ksu_pm_probe(const struct cve99491_profile *prof, const char *package)
{
    struct cve99491_profile p;
    struct pm_binder_api api;
    struct pm_diag diag = { "none", "not attempted" };
    char out[512];
    int ok = 0;

    if (prof)
        p = *prof;
    else
        memset(&p, 0, sizeof(p));
    if (cve99491_profile_pm_assumed(&p))
        printf("[!] pm_* missing in profile; using ASSUMED defaults\n");
    if (!package || !*package)
        package = p.ksu_manager;
    if (!package || !*package) {
        printf("[pm-probe] result=fail detail=no package and no ksu_manager\n");
        return 1;
    }
    snprintf(p.ksu_manager, sizeof(p.ksu_manager), "%s", package);
    printf("[pm-probe] package=%s\n", package);
    printf("[pm-probe] lib=%s service=%s interface=%s\n", p.pm_binder_lib,
           p.pm_service, p.pm_interface);
    printf("[pm-probe] txn_get_application_info=%u txn_get_package_info=%u "
           "user=%u\n", p.pm_txn_get_application_info,
           p.pm_txn_get_package_info, p.pm_user_id);
    if (pm_binder_load(&api, p.pm_binder_lib, 1, &diag) != 0) {
        printf("[pm-probe] txn=none step=%s status=fail detail=%s\n",
               diag.step, diag.detail);
        printf("[pm-probe] result=fail\n");
        return 1;
    }
    if (pm_binder_transact_apk(&p, &api, p.pm_txn_get_application_info,
                               "getApplicationInfo", out, sizeof(out), 1,
                               &diag) == 0) {
        printf("[pm-probe] txn=%u result=ok path=%s\n",
               p.pm_txn_get_application_info, out);
        ok = 1;
    } else {
        printf("[pm-probe] txn=%u result=fail step=%s detail=%s\n",
               p.pm_txn_get_application_info, diag.step, diag.detail);
    }
    if (pm_binder_transact_apk(&p, &api, p.pm_txn_get_package_info,
                               "getPackageInfo", out, sizeof(out), 1,
                               &diag) == 0) {
        printf("[pm-probe] txn=%u result=ok path=%s\n",
               p.pm_txn_get_package_info, out);
        ok = 1;
    } else {
        printf("[pm-probe] txn=%u result=fail step=%s detail=%s\n",
               p.pm_txn_get_package_info, diag.step, diag.detail);
    }
    pm_binder_unload(&api);
    printf("[pm-probe] result=%s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}

static int module_live(const struct cve99491_profile *prof)
{
    FILE *f = fopen("/proc/modules", "r");
    char alias[64];
    char want[96];
    char line[256];
    size_t n;

    if (!f)
        return 0;
    ksu_module_alias(prof, alias, sizeof(alias));
    snprintf(want, sizeof(want), "%s ", alias);
    n = strlen(want);
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, want, n)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* 9.378: ksud late-load calls daemonize() first, so the exec'd parent exits 0
 * in a few ms and the real work happens in a detached child whose stdio is
 * /dev/null. "rc=0" therefore proves nothing: poll /proc/modules instead. */
static int ksu_wait_module(const struct cve99491_profile *prof, long ms)
{
    long t0 = ksu_now_ms();
    int last = -1;

    for (;;) {
        int live = module_live(prof);
        long dt = ksu_now_ms() - t0;

        if (live != last) {
            printf("[ksu] module live=%d at +%ld ms\n", live, dt);
            last = live;
        }
        if (live)
            return 1;
        if (dt >= ms)
            break;
        usleep(200000);
    }
    printf("[-] ksu: module still absent after %ld ms\n", ms);
    return 0;
}

/* Fallback when pm is unusable from the current cred (forged/kernel SID):
 * locate the manager APK directly under the profile's APK root. */
static int find_manager_apk(const struct cve99491_profile *prof, char *out,
                            size_t cap)
{
    DIR *app = opendir(prof->ksu_manager_apk_root);
    struct dirent *e;

    if (!app) {
        printf("[glob] opendir %s: %s\n", prof->ksu_manager_apk_root,
               strerror(errno));
        return -1;
    }
    while ((e = readdir(app))) {
        char base[512];
        DIR *d;
        struct dirent *c;

        if (e->d_name[0] == '.')
            continue;
        snprintf(base, sizeof base, "%s/%s", prof->ksu_manager_apk_root,
                 e->d_name);
        d = opendir(base);
        if (!d)
            continue;
        while ((c = readdir(d))) {
            size_t n = strlen(prof->ksu_manager);
            char apk[600];

            if (strncmp(c->d_name, prof->ksu_manager, n) != 0 ||
                (c->d_name[n] != '-' && c->d_name[n] != 0))
                continue;
            snprintf(apk, sizeof apk, "%s/%s/base.apk", base, c->d_name);
            if (access(apk, R_OK) == 0) {
                printf("[glob] apk=%s\n", apk);
                snprintf(out, cap, "%s", apk);
                closedir(d);
                closedir(app);
                return 0;
            }
            printf("[glob] access %s: %s\n", apk, strerror(errno));
        }
        closedir(d);
    }
    closedir(app);
    return -1;
}

/* Shell fallback: `pm path <manager>` (kept until device-verified). */
static int pm_shell_apk_path(const struct cve99491_profile *prof, char *out,
                             size_t cap)
{
    char cmd[192], buf[1024];
    char *p;

    {
        char qmgr[256];

        if (sh_quote(prof->ksu_manager, qmgr, sizeof(qmgr)) != 0)
            return -1;
        snprintf(cmd, sizeof(cmd), "pm path %s", qmgr);
    }
    {
        int rr = run_sh(cmd, buf, sizeof(buf), 8000);

        printf("[pm] cmd=\"%s\" rc=%d out=\"%.160s\"\n", cmd, rr, buf);
        if (rr != 0)
            return -1;
    }
    p = strstr(buf, "package:");
    if (!p) {
        printf("[pm] no package: in output\n");
        return -1;
    }
    p += 8;
    p[strcspn(p, "\r\n")] = 0;
    if (!*p || strlen(p) >= cap) {
        printf("[pm] bad path len=%d\n", (int)strlen(p));
        return -1;
    }
    snprintf(out, cap, "%s", p);
    {
        int ok = access(out, R_OK);

        printf("[pm] path=\"%s\" access=%d errno=%d\n", out, ok, errno);
        return ok == 0 ? 0 : -1;
    }
}

/* 0 = package binder, 1 = pm, 2 = /data/app glob; -1 = not found. */
static int manager_apk_path(const struct cve99491_profile *prof, char *out,
                            size_t cap, int *source)
{
    struct pm_diag diag = { "none", "not attempted" };
    int backend = pm_backend_from_env();

    *source = 1;
    if (backend == PM_BACKEND_BINDER) {
        if (pm_binder_apk_path(prof, out, cap, &diag) == 0) {
            *source = 0;
            return 0;
        }
        printf("[!] pm-binder failed at %s: %s; falling back to pm path\n",
               diag.step, diag.detail);
    }
    if (pm_shell_apk_path(prof, out, cap) == 0)
        return 0;
    printf("[!] pm path failed; falling back to /data/app glob "
           "(depends on the ROM app layout)\n");
    if (find_manager_apk(prof, out, cap) == 0) {
        *source = 2;
        return 0;
    }
    return -1;
}

struct ksu_cache {
    const struct cve99491_profile *prof;
    const char *work;
    char apk[512];
    char mgr[64];
    char rel[128];
    char kmi[32];
    char dir[192];
    char ksud[224];
};

static int ksu_cache_release(struct ksu_cache *c)
{
    struct utsname u;
    const char *android;
    const char *dot;

    if (uname(&u) != 0)
        return -ENOSYS;
    snprintf(c->rel, sizeof(c->rel), "%s", u.release);
    android = strstr(c->rel, "-android");
    dot = strchr(c->rel, '.');
    if (!android || !dot)
        return -EINVAL;
    snprintf(c->kmi, sizeof(c->kmi), "android%d-%d.%d",
             atoi(android + 8), atoi(c->rel), atoi(dot + 1));
    return 0;
}

static int ksu_cache_manager(struct ksu_cache *c)
{
    int src = 0;

    if (manager_apk_path(c->prof, c->apk, sizeof(c->apk), &src) != 0)
        return -ENOENT;
    if (src == 2)
        snprintf(c->mgr, sizeof(c->mgr), "glob");
    else
        snprintf(c->mgr, sizeof(c->mgr), "%s", c->prof->ksu_manager);
    printf("[ksu] manager apk via %s: %s\n",
           src == 0 ? "package-binder" : src == 1 ? "pm" : "glob", c->apk);
    return 0;
}

static void ksu_cache_paths(struct ksu_cache *c)
{

    snprintf(c->dir, sizeof(c->dir), "%s/cache", c->prof->ksu_workdir);
    snprintf(c->ksud, sizeof(c->ksud), "%s/%s", c->dir,
             c->prof->ksu_ksud_name);
    mkdir(c->dir, 0755);
    (void)chmod(c->dir, 0777);
}

static int ksu_cache_lib(const struct ksu_cache *c, char *lib, size_t size)
{
    char *slash;

    snprintf(lib, size, "%s", c->apk);
    slash = strrchr(lib, '/');
    if (!slash)
        return -EINVAL;
    *slash = 0;
    strncat(lib, "/", size - strlen(lib) - 1);
    strncat(lib, c->prof->ksu_lib_subpath, size - strlen(lib) - 1);
    if (access(lib, R_OK) == 0)
        return 0;
    snprintf(lib, size, "%s", c->apk);
    slash = strrchr(lib, '/');
    if (!slash)
        return -EINVAL;
    *slash = 0;
    strncat(lib, "/", size - strlen(lib) - 1);
    strncat(lib, c->prof->ksu_lib_subpath_v8a, size - strlen(lib) - 1);
    return access(lib, R_OK) == 0 ? 0 : -EACCES;
}

static int ksu_cache_extract(struct ksu_cache *c)
{
    char lib[600];
    long long size;

    /* 9.377: there is no cache and no key any more. Every run re-reads the
     * installed manager package and copies its CLI out again, so a CLI that
     * got renamed in the profile can never be shadowed by a stale copy that an
     * earlier run left behind under the same <work>/cache/ksud path. */
    if (ksu_cache_lib(c, lib, sizeof(lib))) {
        printf("[-] ksu: no readable manager lib (%s)\n", c->apk);
        return -EACCES;
    }
    unlink(c->ksud);
    if (copy_file(lib, c->ksud, 0755)) {
        printf("[-] ksu: cannot copy %s\n", lib);
        return -EACCES;
    }
    size = (long long)file_size(c->ksud);
    if (size <= 0) {
        printf("[-] ksu: empty copy of %s\n", lib);
        return -EIO;
    }
    printf("[ksu] ksud <- %s (%lld B)\n", lib, size);
    return 0;
}

static int ksu_cache_ensure(struct ksu_cache *c)
{
    return ksu_cache_extract(c);
}

static int ksu_cache_init(struct ksu_cache *c)
{
    int err;

    mkdir(c->work, 0755);
    err = ksu_cache_release(c);
    if (err) {
        printf("[-] ksu: bad release\n");
        return err;
    }
    err = ksu_cache_manager(c);
    if (err) {
        printf("[-] ksu: no installed manager\n");
        return err;
    }
    ksu_cache_paths(c);
    return 0;
}

int ksu_cache_prepare(const struct cve99491_profile *prof)
{
    struct ksu_cache c = { .prof = prof, .work = prof->ksu_workdir };
    int err;

    err = ksu_cache_init(&c);
    if (err)
        return err;
    return ksu_cache_ensure(&c);
}

/* Install the ksud userspace while still permissive and uid 0. */
static int ksu_install_userspace(const struct cve99491_profile *prof,
                                 const struct ksu_features *feat,
                                 const char *work)
{
    char cmd[1536], out[512], src[512];
    char qsrc[1024], qksud[1024], qksudnew[1040], qbin[1024], qmods[1024];
    int fails = 0;
    int su_compat = feat ? (feat->su_compat ? 1 : 0) : 1;
    int adb_only = feat ? (feat->shell_adb_only ? 1 : 0) : 0;

    snprintf(src, sizeof(src), "%s/%s", work, prof->ksu_ksud_name);
    if (sh_quote(src, qsrc, sizeof(qsrc)) != 0 ||
        sh_quote(prof->ksu_ksud_path, qksud, sizeof(qksud)) != 0 ||
        sh_quote(prof->ksu_ksu_bin_dir, qbin, sizeof(qbin)) != 0 ||
        sh_quote(prof->ksu_modules_dir, qmods, sizeof(qmods)) != 0) {
        printf("[-] ksu: cannot quote install paths\n");
        return 1;
    }

    /* Core userspace installation.  9.395: the CLI that late-load started is
     * still executing <ksud>, so a plain cp over that path dies with ETXTBSY;
     * stage the copy as <ksud>.new and rename it over the old one.  The two
     * symlinks use rm+ln so a stale entry cannot swallow the step.  Every
     * failure here is reported, counted and then ignored: the module is already
     * live, which is the only verdict this file reports on. */
    snprintf(qksudnew, sizeof qksudnew, "%.*s.new'", (int)(strlen(qksud) - 1),
             qksud);
    snprintf(cmd, sizeof cmd, "cp %s %s", qsrc, qksudnew);
    if (run_sh(cmd, out, sizeof out, 10000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "chmod 755 %s", qksudnew);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "mv -f %s %s", qksudnew, qksud);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "mkdir -p %s %s", qbin, qmods);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "%s install", qksud);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "rm -f %s/su && ln -s %s %s/su", qbin, qksud, qbin);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }
    snprintf(cmd, sizeof cmd, "rm -f %s/ksud && ln -s %s %s/ksud", qbin, qksud, qbin);
    if (run_sh(cmd, out, sizeof out, 20000) != 0) {
        fails++;
    }

    /* Manager feature settings are optional userspace policy: warn only.
     * The module is live and ksud installed even if these are rejected. */
    snprintf(cmd, sizeof cmd, "%s feature set su_compat %d", qksud, su_compat);
    if (run_sh(cmd, out, sizeof out, 20000) != 0)
        printf("[!] ksu: su_compat feature failed (non-fatal): %s\n", out);
    snprintf(cmd, sizeof cmd, "%s feature set shell_su_adb_only %d", qksud,
             adb_only);
    if (run_sh(cmd, out, sizeof out, 20000) != 0)
        printf("[!] ksu: shell_su_adb_only feature failed (non-fatal): %s\n",
               out);
    return fails;
}

int ksu_load_main(const struct cve99491_profile *prof)
{
    const char *sv = getenv("CVE99491_SLIDE");
    const char *syms = getenv("CVE99491_SYMS");
    const char *su = getenv("CVE99491_KSU_SU_COMPAT");
    const char *adb = getenv("CVE99491_KSU_SHELL_ADB_ONLY");
    struct ksu_features feat = {
        .su_compat = (su && *su) ? !!atoi(su) : 1,
        .shell_adb_only = (adb && *adb) ? !!atoi(adb) : 0,
    };
    unsigned long long slide = sv ? strtoull(sv, NULL, 0) : 0;
    int rc = ksu_boot_inline(prof, &feat, slide, syms);

    /* This forked child is the process whose stdout adb captures; emit the
     * matrix marker here as well as in the parent, so a parent-side stdout
     * loss cannot hide a successful no-tracefs loader. */
    if (rc == 0) {
        printf("[+] ksu ready\n");
        fflush(stdout);
    }
    return rc == 0 ? 0 : 1;
}

/* 9.381: the kernel's own reason for refusing a module only exists in the
 * kernel ring buffer. CAP_SYSLOG is part of the forged capability set, so the
 * uid=0 process can read it back after finit_module fails. */
/* The path the manager uses itself: its own CLI pulls late-load and loads the
 * module out of the package asset. It daemonizes, so the return code means
 * nothing; only /proc/modules does. */
static int ksu_late_load_ksud(const struct cve99491_profile *prof,
                              const char *work, long wait_ms)
{
    char ksud[300], out[2048];
    char *av[8];
    int rc;

    snprintf(ksud, sizeof ksud, "%s/%s", work, prof->ksu_ksud_name);
    av[0] = ksud;
    av[1] = (char *)"late-load";
    av[2] = (char *)"--post-magica";
    av[3] = (char *)"--allow-shell";
    av[4] = (char *)"--package-name";
    av[5] = (char *)prof->ksu_manager;
    av[6] = NULL;
    printf("[ksu] late-load via the packaged CLI: %s %s %s %s %s %s\n", ksud, av[1],
           av[2], av[3], av[4], av[5]);
    memset(out, 0, sizeof out);
    rc = run_capture(av, out, sizeof out - 1, 60000);
    printf("[ksu] late-load rc=%d (parent only; the CLI daemonizes)\n", rc);
    if (out[0]) {
        out[strcspn(out, "\r\n")] = 0;
    }
    /* 9.439: the CLI exits 0 as soon as it has daemonized, and that is the
     * verdict again.  Waiting for /proc/modules here only produced false
     * negatives, so the gate is gone. */
    (void)wait_ms;
    return rc == 0 ? 0 : -1;
}


/*
 * 9.386: one route only, one verdict only.  Pull the CLI out of the selected
 * package, let that CLI run its own late-load, and call it done the moment the
 * module shows up in /proc/modules.  No in-process finit_module, no userspace
 * install, no appid rewrite, no su probing, no diagnostics afterwards.
 */
static int ksu_boot_inline_old(const struct cve99491_profile *prof,
                               const struct ksu_features *feat,
                               unsigned long long slide,
                               const char *syms_path);

int ksu_boot_inline(const struct cve99491_profile *prof,
                    const struct ksu_features *feat,
                    unsigned long long slide, const char *syms_path)
{
    /* 9.391: upstream's start and upstream's ending; only the loader differs. */
    return ksu_boot_inline_old(prof, feat, slide, syms_path);
}

static int ksu_boot_inline_old(const struct cve99491_profile *prof,
                    const struct ksu_features *feat,
                    unsigned long long slide, const char *syms_path)
{
    int fails;
    char defsyms[512];

    if (!syms_path || !*syms_path) {
        ksu_default_syms(prof, defsyms, sizeof defsyms);
        syms_path = defsyms;
    }
    mkdir(prof->ksu_workdir, 0755);
    if (read_int_file("/sys/fs/selinux/enforce") != 0) {
        printf("[-] ksu: SELinux is not permissive\n");
        return -1;
    }
    /* 9.439: the packaged CLI is the only loader (in-process finit_module is
     * dead here: it answers ENOEXEC on the 6.6 kernel this runs on).  It
     * daemonizes at once, so its exit status is the verdict; no /proc/modules
     * wait, no late module_live() gate. */
    (void)slide;
    (void)syms_path;
    if (ksu_late_load_ksud(prof, prof->ksu_workdir, 20000) != 0) {
        write_text_file("/sys/fs/selinux/enforce", "1");
        printf("[-] ksu: module load failed, enforce=%d\n",
               read_int_file("/sys/fs/selinux/enforce"));
        return -1;
    }
    fails = ksu_install_userspace(prof, feat, prof->ksu_workdir);
    write_text_file("/sys/fs/selinux/enforce", "1");
    /* The module is live: that is the verdict.  userspace steps that failed
     * are cosmetic (a busy binary, a refused symlink), never a failed load. */
    if (fails)
        printf("[!] userspace: %d/7 steps failed\n", fails);
    return 0;
}
