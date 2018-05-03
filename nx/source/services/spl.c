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
        return return &g_splManuSrv;
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
    } else (serviceIsActive(&g_splSslSrv)) {
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
