#include <msquic.h>

#include "log.h"
#include "types.h"
#include "utils.h"
#include "wtf.h"

wtf_result_t wtf_context_create(const wtf_context_config_t* config, wtf_context_t** context)
{
    if (!config || !context) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
#ifdef WTF_QUIC_BACKEND_NETWORK
    if (config->worker_thread_count || config->enable_load_balancing || config->disable_encryption
        || config->execution_profile != WTF_EXECUTION_PROFILE_LOW_LATENCY) {
        return WTF_ERROR_NOT_SUPPORTED;
    }
#endif

    wtf_context_t* ctx = malloc(sizeof(wtf_context_t));
    if (!ctx) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->config = *config;
    ctx->log_level = config->log_level;
    ctx->log_callback = config->log_callback;
    ctx->log_user_context = config->log_user_context;

    if (mtx_init(&ctx->mutex, mtx_plain) != thrd_success) {
        free(ctx);
        return WTF_ERROR_INTERNAL;
    }

    QUIC_STATUS status = MsQuicOpen2(&ctx->quic_api);
    if (QUIC_FAILED(status)) {
        WTF_LOG_CRITICAL(ctx, "context", "MsQuicOpen2 failed: 0x%x", status);
        mtx_destroy(&ctx->mutex);
        free(ctx);
        return wtf_quic_status_to_result(status);
    }

    QUIC_EXECUTION_PROFILE execution_profile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
    if (config->execution_profile == WTF_EXECUTION_PROFILE_MAX_THROUGHPUT) {
        execution_profile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
    } else if (config->execution_profile == WTF_EXECUTION_PROFILE_REAL_TIME) {
        execution_profile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
    } else if (config->execution_profile == WTF_EXECUTION_PROFILE_SCAVENGER) {
        execution_profile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
    }

    const QUIC_REGISTRATION_CONFIG reg_config = {.AppName = "libwtf",
                                                 .ExecutionProfile = execution_profile};

    status = ctx->quic_api->RegistrationOpen(&reg_config, &ctx->registration);
    if (QUIC_FAILED(status)) {
        WTF_LOG_CRITICAL(ctx, "context", "RegistrationOpen failed: 0x%x", status);
        MsQuicClose(ctx->quic_api);
        mtx_destroy(&ctx->mutex);
        free(ctx);
        return wtf_quic_status_to_result(status);
    }
    ctx->quic_api->SetContext(ctx->registration, ctx);

    WTF_LOG_INFO(ctx, "context", "WebTransport context created successfully");

    *context = ctx;
    return WTF_SUCCESS;
}

void wtf_context_destroy(wtf_context_t* context)
{
    if (!context) {
        return;
    }

    wtf_context* ctx = context;

    WTF_LOG_INFO(ctx, "context", "Destroying WebTransport context");

    wtf_server* server = NULL;
    wtf_client* client = NULL;

    mtx_lock(&ctx->mutex);
    server = ctx->server;
    client = ctx->client;
    ctx->server = NULL;
    ctx->client = NULL;
    mtx_unlock(&ctx->mutex);

    if (server) {
        wtf_server_destroy((wtf_server_t*)server);
    }
    if (client) {
        wtf_client_destroy((wtf_client_t*)client);
    }

    mtx_lock(&ctx->mutex);

    if (ctx->registration) {
        ctx->quic_api->RegistrationClose(ctx->registration);
        ctx->registration = NULL;
    }

    if (ctx->quic_api) {
        MsQuicClose(ctx->quic_api);
        ctx->quic_api = NULL;
    }

    mtx_unlock(&ctx->mutex);
    mtx_destroy(&ctx->mutex);

    free(context);
}

wtf_result_t wtf_context_set_log_level(wtf_context_t* context, wtf_log_level_t level)
{
    if (!context) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_context* ctx = context;

    mtx_lock(&ctx->mutex);
    ctx->log_level = level;
    mtx_unlock(&ctx->mutex);

    return WTF_SUCCESS;
}
