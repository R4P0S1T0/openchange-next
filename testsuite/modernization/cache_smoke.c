/* Actual cache file I/O and process handling, using disposable private files. */
#include "mapiproxy/modules/mpm_cache.c"
#include "mapiproxy/modules/mpm_cache_stream.c"
#include <ftw.h>

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "cache check failed at %d: %s\n", __LINE__, #c); \
    return 1; \
} } while (0)

static bool fork_failure, interrupted_wait;
pid_t __real_fork(void);
pid_t __wrap_fork(void);
pid_t __real_waitpid(pid_t, int *, int);
pid_t __wrap_waitpid(pid_t, int *, int);
pid_t __wrap_fork(void)
{
    if (fork_failure) { errno = EAGAIN; return -1; }
    return __real_fork();
}
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    if (interrupted_wait) { interrupted_wait = false; errno = EINTR; return -1; }
    return __real_waitpid(pid, status, options);
}
struct server_id dcesrv_server_id(struct dcesrv_connection *conn)
{
    return (struct server_id){ .pid = 7 };
}

static int remove_entry(const char *path, const struct stat *sb, int type, struct FTW *info)
{
    return remove(path);
}
static int file_contents(const char *path, const char *expected)
{
    char buffer[16] = {0};
    FILE *fp = fopen(path, "rb");
    size_t got;
    if (fp == NULL) return 0;
    got = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    return got == strlen(expected) && memcmp(buffer, expected, got) == 0;
}

static int rpc_bounds(TALLOC_CTX *ctx)
{
    struct mapi_request request = { .length = 30, .mapi_len = 38 };
    struct mapi_response response = { .length = 8, .mapi_len = 12 };
    struct EcDoRpc rpc = { .in.mapi_request = &request, .out.mapi_response = &response };
    struct dcesrv_call_state call = {0};
    struct mapiproxy proxy = {0};
    request.mapi_req = talloc_zero_array(ctx, struct EcDoRpc_MAPI_REQ, 2);
    request.handles = talloc_zero_array(ctx, uint32_t, 2);
    response.mapi_repl = talloc_zero_array(ctx, struct EcDoRpc_MAPI_REPL, 2);
    response.handles = talloc_zero_array(ctx, uint32_t, 1);
    CHECK(request.mapi_req && request.handles && response.mapi_repl && response.handles);
    call.pkt.u.request.opnum = NDR_ECDORPC;
    request.mapi_req[0].opnum = op_MAPI_OpenMessage;
    request.mapi_req[0].u.mapi_OpenMessage.handle_idx = 1;
    response.mapi_repl[0].opnum = op_MAPI_OpenMessage;
    CHECK(cache_request_valid(&request) && cache_response_valid(&response));
    CHECK(NT_STATUS_EQUAL(cache_push(&call, ctx, &rpc), NT_STATUS_INVALID_PARAMETER)); /* Output slot missing. */
    request.mapi_req[0].handle_idx = 2;
    CHECK(!cache_request_valid(&request));
    CHECK(NT_STATUS_EQUAL(cache_pull(&call, ctx, &rpc), NT_STATUS_INVALID_PARAMETER));
    CHECK(NT_STATUS_EQUAL(cache_dispatch(&call, ctx, &rpc, &proxy), NT_STATUS_INVALID_PARAMETER));
    request.mapi_req[0].handle_idx = 0; request.mapi_req[0].u.mapi_OpenMessage.handle_idx = 2;
    CHECK(!cache_request_valid(&request)); request.mapi_req[0].u.mapi_OpenMessage.handle_idx = 1;
    request.mapi_req[1] = request.mapi_req[0]; CHECK(!cache_request_valid(&request));
    memset(&request.mapi_req[1], 0, sizeof(request.mapi_req[1]));
    request.mapi_len = 29; CHECK(!cache_request_valid(&request));
    request.mapi_len = 37; CHECK(!cache_request_valid(&request));
    request.mapi_len = 42; CHECK(!cache_request_valid(&request)); /* Allocation smaller than advertised. */
    request.mapi_len = 30 + 257 * 4; CHECK(!cache_request_valid(&request)); request.mapi_len = 38;
    response.mapi_repl[0].handle_idx = 1; CHECK(!cache_response_valid(&response));
    CHECK(NT_STATUS_EQUAL(cache_push(&call, ctx, &rpc), NT_STATUS_INVALID_PARAMETER));
    response.mapi_repl[0].opnum = op_MAPI_Notify; response.mapi_repl[0].handle_idx = 255;
    CHECK(cache_response_valid(&response));
    response.mapi_repl[1] = response.mapi_repl[0]; CHECK(!cache_response_valid(&response));
    return 0;
}

static int rpc_correlations(TALLOC_CTX *ctx, const char *root)
{
    struct mapi_request request = { .length = 30, .mapi_len = 38 };
    struct mapi_response response = { .length = 14, .mapi_len = 22 };
    struct EcDoRpc rpc = { .in.mapi_request = &request, .out.mapi_response = &response };
    struct dcesrv_connection connection = {0};
    struct dcesrv_connection_context context = { .context_id = 5 };
    struct dcesrv_call_state call = { .conn = &connection, .context = &context };
    struct mpm_message *message, *next;
    char *database = talloc_asprintf(ctx, "tdb://%s/correlations.ldb", root);
    CHECK(database && NT_STATUS_IS_OK(mpm_cache_ldb_createdb(mpm, database, &mpm->ldb_ctx)));
    request.mapi_req = talloc_zero_array(ctx, struct EcDoRpc_MAPI_REQ, 4);
    request.handles = talloc_zero_array(ctx, uint32_t, 2);
    response.mapi_repl = talloc_zero_array(ctx, struct EcDoRpc_MAPI_REPL, 4);
    response.handles = talloc_zero_array(ctx, uint32_t, 2);
    CHECK(request.mapi_req && request.handles && response.mapi_repl && response.handles);
    call.pkt.u.request.opnum = NDR_ECDORPC;
    for (int i = 0; i < 2; i++) {
        request.mapi_req[i].opnum = op_MAPI_OpenMessage;
        request.mapi_req[i].u.mapi_OpenMessage.handle_idx = i;
        request.mapi_req[i].u.mapi_OpenMessage.FolderId = 100;
        request.mapi_req[i].u.mapi_OpenMessage.MessageId = i + 1;
        response.mapi_repl[i].opnum = op_MAPI_OpenMessage;
        response.mapi_repl[i].handle_idx = i;
        response.handles[i] = 1000 + i;
    }
    CHECK(NT_STATUS_IS_OK(cache_pull(&call, ctx, &rpc)));
    CHECK(mpm->messages && mpm->messages->next && mpm->messages->next->next == NULL);
    response.mapi_repl[1].handle_idx = 0;
    CHECK(NT_STATUS_EQUAL(cache_push(&call, ctx, &rpc), NT_STATUS_INVALID_PARAMETER));
    for (message = mpm->messages; message; message = message->next) CHECK(message->handle == UINT32_MAX);
    response.mapi_repl[1].handle_idx = 1;
    CHECK(NT_STATUS_IS_OK(cache_push(&call, ctx, &rpc)));
    for (message = mpm->messages; message; message = message->next) CHECK(message->handle == 999 + message->MessageId);
    /* Releases have no reply; notifications do not consume a request. */
    request.mapi_req[2] = request.mapi_req[1]; request.mapi_req[1].opnum = op_MAPI_Release;
    response.mapi_repl[2] = response.mapi_repl[1]; response.mapi_repl[1].opnum = op_MAPI_Notify;
    CHECK(cache_request_valid(&request) && cache_response_valid(&response) && cache_replies_match(&request, &response));
    response.mapi_repl[2].opnum = op_MAPI_OpenAttach;
    CHECK(!cache_replies_match(&request, &response));
    message = mpm->messages;
    while (message) {
        next = message->next; DLIST_REMOVE(mpm->messages, message);
        talloc_free(message->session); talloc_free(message); message = next;
    }
    return 0;
}

int main(void)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    char root[] = "/tmp/openchange-cache-XXXXXX";
    char outside[] = "/tmp/openchange-cache-outside-XXXXXX";
    char *path, *victim, *directory, *original, *source, *copy_target;
    struct mpm_stream *stream;
    struct mpm_message *message;
    struct mpm_cache *saved;
    struct dcesrv_context *dce;
    struct stat sb;
    uint8_t buffer[16], *data = buffer;
    size_t length;
    FILE *fp;
    pid_t other_child;
    int status, fd;
    char *success[] = {"/bin/true", NULL};
    char *failure[] = {"/bin/false", NULL};
    char *missing[] = {"/no-such-openchange-sync-command", NULL};
    char *signalled[] = {"/bin/sh", "-c", "kill -TERM $$", NULL};
    char *copy_command[4];

    CHECK(ctx != NULL && mkdtemp(root) != NULL && mkdtemp(outside) != NULL);
    CHECK(rpc_bounds(ctx) == 0);
    mpm = talloc_zero(ctx, struct mpm_cache);
    CHECK(mpm != NULL);
    talloc_set_destructor(mpm, cache_destructor);
    mpm->dbpath = root;
    CHECK(rpc_correlations(ctx, root) == 0);
    stream = talloc_zero(mpm, struct mpm_stream);
    message = talloc_zero(stream, struct mpm_message);
    CHECK(stream != NULL && message != NULL);
    message->FolderId = 1; message->MessageId = 2;
    stream->message = message;
    stream->StreamSize = 4;
    mpm->streams = stream;
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    original = talloc_strdup(ctx, stream->filename);
    CHECK(original != NULL);
    CHECK(fstat(fileno(stream->fp), &sb) == 0 && (sb.st_mode & 0777) == 0600);
    CHECK(fcntl(fileno(stream->fp), F_GETFD) & FD_CLOEXEC);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_write(stream, 0, NULL)) && stream->offset == 0);
    {
        uint8_t *empty = NULL;
        CHECK(NT_STATUS_IS_OK(mpm_cache_stream_read(stream, 0, &length, &empty)) && length == 0);
    }
    directory = talloc_asprintf(ctx, "%s/0x1", root);
    CHECK(directory != NULL && stat(directory, &sb) == 0 && (sb.st_mode & 0777) == 0700);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_write(stream, 4, (uint8_t *)"test")));
    CHECK(NT_STATUS_EQUAL(mpm_cache_stream_write(stream, 1, (uint8_t *)"x"), NT_STATUS_INVALID_PARAMETER));
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_reset(stream)));
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_read(stream, sizeof(buffer), &length, &data)));
    CHECK(length == 4 && memcmp(data, "test", 4) == 0);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_read(stream, 1, &length, &data)) && length == 0);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_close(stream)) && stream->fp == NULL);
    CHECK(NT_STATUS_EQUAL(mpm_cache_stream_close(stream), NT_STATUS_NOT_FOUND));
    CHECK(NT_STATUS_EQUAL(mpm_cache_stream_read(stream, 1, &length, &data), NT_STATUS_INVALID_PARAMETER));
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_write(stream, 1, (uint8_t *)"x"))); /* Read-only reopen. */
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_close(stream)));
    stream->StreamSize = 5;
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)) && stream->fp == NULL);
    stream->StreamSize = 4;

    /* Root access, traversal, directory links, file links, hardlinks and FIFOs fail closed. */
    CHECK(chmod(root, 0755) == 0 && mpm_cache_open_root(mpm) == -1);
    CHECK(chmod(root, 0700) == 0);
    CHECK(chmod(directory, 0755) == 0);
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(chmod(directory, 0700) == 0);
    victim = talloc_asprintf(ctx, "%s/victim", outside);
    CHECK(victim != NULL);
    fp = fopen(victim, "wb"); CHECK(fp != NULL);
    CHECK(fwrite("keep", 1, 4, fp) == 4 && fclose(fp) == 0);
    stream->filename = victim;
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    path = talloc_asprintf(ctx, "%s/../%s/victim", root, strrchr(outside, '/') + 1);
    stream->filename = path;
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    path = talloc_asprintf(ctx, "%s/redirect", root);
    CHECK(path != NULL && symlink(outside, path) == 0);
    stream->filename = talloc_asprintf(ctx, "%s/redirect/victim", root);
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(unlink(original) == 0 && symlink(victim, original) == 0);
    stream->filename = NULL;
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(file_contents(victim, "keep"));
    CHECK(unlink(original) == 0 && link(victim, original) == 0);
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)) && file_contents(victim, "keep"));
    CHECK(unlink(original) == 0 && mkfifo(original, 0600) == 0);
    CHECK(!NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(unlink(original) == 0);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_write(stream, 4, (uint8_t *)"test")));

    /* exec failure, nonzero/signal exits, fork failure and EINTR are distinct from success. */
    mpm->sync_cmd = missing;
    CHECK(!NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && !stream->cached && stream->fp == NULL);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    mpm->sync_cmd = failure;
    CHECK(!NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && !stream->cached);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    mpm->sync_cmd = signalled;
    CHECK(!NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && !stream->cached);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    mpm->sync_cmd = success;
    fork_failure = true;
    CHECK(!NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && !stream->cached);
    fork_failure = false;
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    other_child = __real_fork();
    CHECK(other_child != -1);
    if (other_child == 0) _exit(42);
    interrupted_wait = true;
    CHECK(NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && stream->cached);
    CHECK(waitpid(other_child, &status, 0) == other_child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_close(stream)));

    source = talloc_asprintf(ctx, "%s/source", root);
    copy_target = talloc_asprintf(ctx, "%s/copy target;'$()", root);
    CHECK(source != NULL && copy_target != NULL);
    fp = fopen(source, "wb"); CHECK(fp != NULL);
    CHECK(fwrite("data", 1, 4, fp) == 4 && fclose(fp) == 0);
    fp = fopen(copy_target, "wb"); CHECK(fp != NULL);
    CHECK(fwrite("orig", 1, 4, fp) == 4 && fclose(fp) == 0);
    stream->filename = copy_target;
    CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
    copy_command[0] = "/bin/cp"; copy_command[1] = source; copy_command[2] = "__FILE__"; copy_command[3] = NULL;
    mpm->sync_cmd = copy_command;
    CHECK(NT_STATUS_IS_OK(cache_exec_sync_cmd(stream)) && stream->cached);
    CHECK(file_contents(copy_target, "data"));

    /* Only a single bounded read with one handle is synthesized locally. */
    {
        struct dcesrv_call_state call = {0};
        struct dcesrv_connection conn = {0};
        struct dcesrv_connection_context context = { .context_id = 3 };
        struct server_id id = { .pid = 7 };
        struct EcDoRpc rpc = {0};
        struct mapiproxy proxy = {0};
        struct ndr_push *ndr;
        stream->session = mpm_session_new(stream, id, 3);
        CHECK(stream->session != NULL);
        stream->handle = 0x1234;
        call.conn = &conn; call.context = &context;
        call.pkt.u.request.opnum = NDR_ECDORPC;
        rpc.in.max_data = UINT16_MAX;
        rpc.in.mapi_request = talloc_zero(ctx, struct mapi_request);
        rpc.out.mapi_response = talloc_zero(ctx, struct mapi_response);
        rpc.out.length = talloc_zero(ctx, uint16_t);
        CHECK(rpc.in.mapi_request && rpc.out.mapi_response && rpc.out.length);
        rpc.in.mapi_request->mapi_req = talloc_zero_array(ctx, struct EcDoRpc_MAPI_REQ, 3);
        rpc.in.mapi_request->handles = talloc_zero_array(ctx, uint32_t, 2);
        CHECK(rpc.in.mapi_request->mapi_req && rpc.in.mapi_request->handles);
        rpc.in.mapi_request->length = 7;
        rpc.in.mapi_request->mapi_len = 11;
        rpc.in.mapi_request->handles[0] = stream->handle;
        rpc.in.mapi_request->mapi_req[0].opnum = op_MAPI_ReadStream;
        rpc.in.mapi_request->mapi_req[0].u.mapi_ReadStream.ByteCount = 4;
        CHECK(NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && proxy.norelay);
        CHECK(rpc.out.mapi_response->mapi_repl[1].opnum == 0);
        CHECK(rpc.out.mapi_response->mapi_repl[0].u.mapi_ReadStream.data.length == 4);
        CHECK(memcmp(rpc.out.mapi_response->mapi_repl[0].u.mapi_ReadStream.data.data, "data", 4) == 0);
        ndr = ndr_push_init_ctx(ctx); CHECK(ndr != NULL);
        CHECK(NDR_ERR_CODE_IS_SUCCESS(ndr_push_mapi_response(ndr, NDR_SCALARS, rpc.out.mapi_response)));
        CHECK(ndr->offset == *rpc.out.length && ndr->offset == 18);
        CHECK(NT_STATUS_IS_OK(mpm_cache_stream_reset(stream)));
        proxy.norelay = false;
        rpc.in.mapi_request->mapi_req[1] = rpc.in.mapi_request->mapi_req[0];
        CHECK(NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && !proxy.norelay);
        rpc.in.mapi_request->mapi_req[1].opnum = 0;
        rpc.in.mapi_request->mapi_len = 15; /* Two handles: relay the original request. */
        CHECK(NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && !proxy.norelay);
        rpc.in.mapi_request->mapi_len = 11;
        rpc.in.max_data = 4;
        CHECK(NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && !proxy.norelay);
        rpc.in.max_data = UINT16_MAX;
        {
            struct EcDoRpc_MAPI_REPL *replies = rpc.out.mapi_response->mapi_repl;
            stream->cached = false; stream->ahead = true; proxy.ahead = true;
            rpc.out.mapi_response->mapi_repl = NULL;
            CHECK(NT_STATUS_EQUAL(cache_dispatch(&call, ctx, &rpc, &proxy), NT_STATUS_INVALID_PARAMETER));
            rpc.out.mapi_response->mapi_repl = replies;
            replies[0].error_code = MAPI_E_CALL_FAILED;
            CHECK(NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && !proxy.ahead && !stream->ahead);
            CHECK(stream->offset == 0);
            replies[0].error_code = MAPI_E_SUCCESS; stream->cached = true;
        }
        CHECK(NT_STATUS_IS_OK(mpm_cache_stream_close(stream)));
        CHECK(!NT_STATUS_IS_OK(cache_dispatch(&call, ctx, &rpc, &proxy)) && !proxy.norelay);
        CHECK(NT_STATUS_IS_OK(mpm_cache_stream_open(mpm, stream)));
        {
            struct EcDoRpc_MAPI_REPL reply = {0};
            reply.opnum = op_MAPI_ReadStream;
            reply.u.mapi_ReadStream.data.length = 2;
            reply.u.mapi_ReadStream.data.data = (uint8_t *)"da";
            stream->cached = false;
            mpm->sync = true; mpm->sync_min = 0; mpm->sync_cmd = success;
            CHECK(NT_STATUS_IS_OK(cache_push_ReadStream(&call, rpc.in.mapi_request->mapi_req[0], reply, &rpc)));
            CHECK(stream->cached && stream->offset == 2);
            CHECK(NT_STATUS_IS_OK(mpm_cache_stream_read(stream, 2, &length, &data)));
            CHECK(length == 2 && memcmp(data, "ta", 2) == 0);
            reply.error_code = MAPI_E_CALL_FAILED;
            reply.u.mapi_ReadStream.data.length = SIZE_MAX;
            reply.u.mapi_ReadStream.data.data = NULL;
            CHECK(NT_STATUS_IS_OK(cache_push_ReadStream(&call, rpc.in.mapi_request->mapi_req[0], reply, &rpc)));
            CHECK(stream->offset == 4);
        }
    }

    /* Configuration failures preserve the working cache and reject unsafe roots/commands. */
    dce = talloc_zero(ctx, struct dcesrv_context);
    CHECK(dce != NULL);
    dce->lp_ctx = loadparm_init(dce);
    CHECK(dce->lp_ctx != NULL);
    saved = mpm;
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER) && mpm == saved);
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:path", root));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:sync", "true"));
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER) && mpm == saved);
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:sync_cmd", "relative-command"));
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:sync_cmd", "/bin/true"));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:sync_min", "-1"));
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:sync_min", "0"));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:ahead", "true"));
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER));
    CHECK(lpcfg_set_cmdline(dce->lp_ctx, "mpm_cache:ahead", "false"));
    path = talloc_asprintf(ctx, "%s/%s", root, MPM_DB);
    CHECK(path != NULL && symlink(victim, path) == 0);
    CHECK(NT_STATUS_EQUAL(cache_init(dce), NT_STATUS_INVALID_PARAMETER) && mpm == saved);
    CHECK(file_contents(victim, "keep") && unlink(path) == 0);
    CHECK(NT_STATUS_IS_OK(cache_init(dce)) && mpm != saved);
    CHECK(stat(path, &sb) == 0 && (sb.st_mode & 0777) == 0600);
    fd = mpm_cache_open_root(mpm); CHECK(fd != -1 && close(fd) == 0);
    talloc_free(dce);
    CHECK(mpm == NULL);
    talloc_free(ctx);
    CHECK(nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS) == 0);
    CHECK(nftw(outside, remove_entry, 8, FTW_DEPTH | FTW_PHYS) == 0);
    puts("Cache private file I/O, path confinement, sync process failure and configuration checks passed");
    return 0;
}
