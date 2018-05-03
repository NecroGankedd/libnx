// Copyright 2018 SciresM
#include <string.h>
#include "types.h"
#include "result.h"
#include "arm/atomics.h"
#include "kernel/ipc.h"
#include "kernel/detect.h"
#include "services/sm.h"
#include "services/spl.h"

static Service g_splSrv, g_splCryptoSrv, g_splSslSrv, g_splEsSrv, g_splFsSrv, g_splManuSrv;
static u64 g_splRefCnt, g_splCryptoRefCnt, g_splSslRefCnt, g_splEsRefCnt, g_splFsRefCnt, g_splManuRefCnt;

/* Helper prototypes for accessing handles. */
Service *_splGetGeneralSrv(void);
Service *_splGetCryptoSrv(void);
Service *_splGetRsaSrv(void);

Service *_splGetGeneralSrv(void) {
    if (!kernelAbove400()) {
        return &g_splSrv;
    }
    
    if (serviceIsActive(&g_splSrv)) {
        return &g_splSrv;
    } else {
        return _splGetCryptoSrv();
    }
}

Service *_splGetCryptoSrv(void) {
    if (!kernelAbove400()) {
        return &g_splSrv;
    }
    
    if (serviceIsActive(&g_splManuSrv)) {
        return &g_splManuSrv;
    } else if (serviceIsActive(&g_splFsSrv)) {
        return &g_splFsSrv;
    } else if (serviceIsActive(&g_splEsSrv)) {
        return &g_splEsSrv;
    } else if (serviceIsActive(&g_splSslSrv)) {
        return &g_splSslSrv;
    } else {
        return &g_splCryptoSrv;
    }
}

Service *_splGetRsaSrv(void) {
    if (!kernelAbove400()) {
        return &g_splSrv;
    }
    
    if (serviceIsActive(&g_splFsSrv)) {
        return &g_splFsSrv;
    } else if (serviceIsActive(&g_splEsSrv)) {
        return &g_splEsSrv;
    } else {
        return &g_splSslSrv;
    } 
}

/* There are like six services, so these helpers will initialize/exit the relevant services. */
Result _splSrvInitialize(Service *srv, u64 *refcnt, const char *name) {
    atomicIncrement64(refcnt);
    
    if (serviceIsActive(srv))
        return 0;
    
    return smGetService(srv, name);
}

void _splSrvExit(Service *srv, u64 *refcnt) {
    if (atomicDecrement64(refcnt) == 0)
        serviceClose(srv);
}

Result splInitialize(void) {
    return _splSrvInitialize(&g_splSrv, &g_splRefCnt, "spl:");
}

void splExit(void) {
    return _splSrvExit(&g_splSrv, &g_splRefCnt);
}

Result splCryptoInitialize(void) {
    if (kernelAbove400()) {
        return _splSrvInitialize(&g_splCryptoSrv, &g_splCryptoRefCnt, "spl:mig");
    } else {
        return splInitialize();
    }
}

void splCryptoExit(void) {
    if (kernelAbove400()) {
        return _splSrvExit(&g_splCryptoSrv, &g_splCryptoRefCnt);
    } else {
        return splExit();
    }
}

Result splSslInitialize(void) {
    if (kernelAbove400()) {
        return _splSrvInitialize(&g_splSslSrv, &g_splSslRefCnt, "spl:ssl");
    } else {
        return splInitialize();
    }
}

void splSslExit(void) {
    if (kernelAbove400()) {
        return _splSrvExit(&g_splSslSrv, &g_splSslRefCnt);
    } else {
        return splExit();
    }
}

Result splEsInitialize(void) {
    if (kernelAbove400()) {
        return _splSrvInitialize(&g_splEsSrv, &g_splEsRefCnt, "spl:es");
    } else {
        return splInitialize();
    }
}

void splEsExit(void) {
    if (kernelAbove400()) {
        return _splSrvExit(&g_splEsSrv, &g_splEsRefCnt);
    } else {
        return splExit();
    }
}

Result splFsInitialize(void) {
    if (kernelAbove400()) {
        return _splSrvInitialize(&g_splFsSrv, &g_splFsRefCnt, "spl:fs");
    } else {
        return splInitialize();
    }
}

void splFsExit(void) {
    if (kernelAbove400()) {
        return _splSrvExit(&g_splFsSrv, &g_splFsRefCnt);
    } else {
        return splExit();
    }
}

Result splManuInitialize(void) {
    return _splSrvInitialize(&g_splManuSrv, &g_splManuRefCnt, "spl:manu");
}

void splManuExit(void) {
     return _splSrvExit(&g_splManuSrv, &g_splManuRefCnt);
}


/* SPL IGeneralService functionality. */
Result splGetConfig(SplConfigItem config_item, u64 *out_config) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u32 config_item;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 0;
    raw->config_item = config_item;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u64 out;
        } *resp = r.Raw;

        rc = resp->result;
        if (R_SUCCEEDED(rc)) {
            *out_config = resp->out;
        }
    }

    return rc;
}

Result splUserExpMod(void *input, void *modulus, void *exp, size_t exp_size, void *dst) {
    IpcCommand c;
    ipcInitialize(&c);
    
    ipcAddSendStatic(&c, input, SPL_RSA_BUFFER_SIZE, 0);
    ipcAddSendStatic(&c, exp, exp_size, 1);
    ipcAddSendStatic(&c, modulus, SPL_RSA_BUFFER_SIZE, 2);
    ipcAddRecvStatic(&c, dst, SPL_RSA_BUFFER_SIZE, 0);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 1;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }

    return rc;
}

Result splSetConfig(SplConfigItem config_item, u64 value) {
    IpcCommand c;
    ipcInitialize(&c);

    struct PACKED {
        u64 magic;
        u64 cmd_id;
        u32 config_item;
        u64 value;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 5;
    raw->config_item = config_item;
    raw->value = value;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }

    return rc;
}

Result splGetRandomBytes(void *out, size_t out_size) {
    IpcCommand c;
    ipcInitialize(&c);
    
    ipcAddRecvStatic(&c, out, out_size, 0);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 7;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }

    return rc;
}

Result splIsDevelopment(u8 *out_is_development) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 11;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u8 is_development;
        } *resp = r.Raw;

        rc = resp->result;
        if (R_SUCCEEDED(rc)) {
            *out_is_development = resp->is_development;
        }
    }

    return rc;
}

Result splSetSharedData(u32 value) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
        u32 value;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 24;
    raw->value = value;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
        } *resp = r.Raw;

        rc = resp->result;
    }

    return rc;
}

Result splGetSharedData(u32 *out_value) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 25;

    Result rc = serviceIpcDispatch(_splGetGeneralSrv());

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        ipcParse(&r);

        struct {
            u64 magic;
            u64 result;
            u32 value;
        } *resp = r.Raw;

        rc = resp->result;
        
        if (R_SUCCEEDED(rc)) {
            *out_value = resp->value;
        }
    }

    return rc;
}