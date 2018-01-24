/* encoding:utf-8 */

/* Copyright (c) 2018, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include <p11-kit/pkcs11.h>
#include "pkcs11-probe.h"

typedef struct dll_instance_t *dll_t;
extern dll_t new_dll_instance();
extern void delete_dll_instance(dll_t instance);
extern probe_result_t dll_probe(dll_t dll, const char *lib);
extern const char *dll_which_lib(dll_t dll);

typedef void (*instance_cleanup_func_t)(void *instance);

struct dll_instance_t {
    void *handle;
    char *from_which_lib;
    instance_cleanup_func_t cleanup;
};

static void dummy_instance_cleanup(void *instance)
{
    (void) instance; /* gcc -Wunused-parameter */
}

static void dll_instance_init(struct dll_instance_t *instance)
{
    instance->handle = NULL;
    instance->from_which_lib = NULL;
    instance->cleanup = dummy_instance_cleanup;
}

static void dll_instance_cleanup(void *instance)
{
    dll_t dll;

    dll = instance;
    if (dll->handle) {
        dlclose(dll->handle);
        dll->handle = NULL;
    }
    if (dll->from_which_lib) {
        free(dll->from_which_lib);
        dll->from_which_lib = NULL;
    }
    dll->cleanup = dummy_instance_cleanup;
}


#include <string.h>

#ifndef __USE_XOPEN2K8
static char *strndup(const char *s, size_t n)
{
    char *dst;
    char *compact;
    int i;

    dst = malloc(n + 1);

    for (i = 0; i < n && *s; i++, s++) {
        dst[i] = *s;
    }
    dst[i] = '\0';
    if (i < n && (compact = realloc(dst, i + 1))) {
        dst = compact;
    }
    return dst;
}
#endif /* __USE_XOPEN2K8 */

probe_result_t dll_probe(dll_t self, const char *lib)
{
    void *handle;

    assert(self);
    self->cleanup(self);

    handle = NULL;
    handle = dlopen(lib, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Error! Failed to open '%s': %s\n", lib, dlerror());
        return PROBE_GENERIC_FAILURE;
    }

    self->handle = handle;
    const int MAX_BYTES = /* Hard-coded max filepath length: */ 1024;
    self->from_which_lib = strndup(lib, MAX_BYTES);
    self->cleanup = dll_instance_cleanup;
    return (PROBE_SUCCESS);
}

const char *dll_which_lib(dll_t self)
{
    return (self->from_which_lib);
}

struct pkcs11_instance_t {
    struct dll_instance_t dll;
    CK_FUNCTION_LIST_PTR functions;
    instance_cleanup_func_t cleanup;
};

static void pkcs11_instance_cleanup(void *instance)
{
    pkcs11_t u;

    u.ptr = instance;

    /* First, clean up sub items. */
    u.dll->cleanup(instance);
    /* Then reset each member variable. */
    u.pkcs11->functions = NULL;
    /* Last, relink clean-up function pointer to the dummy one. */
    u.pkcs11->cleanup = dummy_instance_cleanup;
}

probe_result_t pkcs11_probe(pkcs11_t self, const char *lib)
{
    CK_FUNCTION_LIST_PTR functions;
    CK_C_GetFunctionList C_GetFunctionList;

    assert(self.ptr);

    self.pkcs11->cleanup(self.ptr);

    if (lib && '\0' != lib[0]) {
        int rc = dll_probe(self.dll, lib);
        if (rc != PROBE_SUCCESS) {
            return rc;
        }
    }
    if (!lib || '\0' == lib[0]) {
        /* 如果调用者未指定动态库名称, 则从下列备选项中依次进行尝试 */
        const char *list[] = {"/usr/lib/opencryptoki/libopencryptoki.so", NULL};
        lib = list[0];
        do {
            if (dll_probe(self.dll, lib) == PROBE_SUCCESS) {
                break;
            }
            ++lib;
        } while(lib);
    }
    if (!lib) {
        return PROBE_GENERIC_FAILURE;
    }
    self.pkcs11->cleanup = pkcs11_instance_cleanup;

    /* Get the list of the PKCS11 functions this token supports */
    C_GetFunctionList = (CK_C_GetFunctionList) dlsym(self.dll->handle, "C_GetFunctionList");
    if (!C_GetFunctionList) {
        int rc = errno;
        fprintf(stderr, "Error getting function list from DLL: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }
    functions = NULL;
    C_GetFunctionList(&functions);
    /* FIXME: Error cases returned by C_GetFunctionList() should be checked here. */
    self.pkcs11->functions = functions;
    return PROBE_SUCCESS;
}

const char *pkcs11_which_lib(pkcs11_t instance)
{
    return (dll_which_lib(instance.dll));
}

const CK_FUNCTION_LIST_PTR pkcs11_get_function_list(pkcs11_t instance)
{
    return (instance.pkcs11->functions);
}

static void pkcs11_instance_init(struct pkcs11_instance_t *instance)
{
    assert(instance);

    dll_instance_init(&(instance->dll));
    instance->functions = NULL;
    instance->cleanup = dummy_instance_cleanup;
}

pkcs11_t new_pkcs11_instance()
{
    struct pkcs11_instance_t *instance;

    instance = malloc(sizeof(struct pkcs11_instance_t));
    assert(instance);
    pkcs11_instance_init(instance);
    return ((pkcs11_t) instance);
}

void delete_pkcs11_instance(pkcs11_t instance)
{
    if (!instance.ptr) {
        return;
    }
    instance.pkcs11->cleanup(instance.ptr);
    free(instance.pkcs11);
}
