extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <dlfcn.h>
}
#include <v8.h>
#include <v8-debug.h>

using namespace v8;

extern ngx_module_t  ngx_http_v8_module;

template <class T>
inline T ptr_cast(void *p) {
    return static_cast<T>(p);
}

typedef struct {
    Persistent<Value> handle;
} handle_t;

typedef struct {
    Persistent<Function> fun;
} function_t;

typedef struct {
    Persistent<Object> recv;
    Persistent<Function> fun;
} method_t;

typedef struct {
    ngx_chain_t *head;
    ngx_chain_t *tail;
    size_t size;
} brigade_t;

typedef struct {
    ngx_uint_t    hash;
    ngx_str_t     name;
    ngx_str_t     value;
} var_t;

typedef struct {
    ngx_uint_t agent_port;
} ngx_http_v8_main_conf_t;

typedef struct {
    Persistent<Context> context;
    Persistent<Function> process;
    Persistent<ObjectTemplate> classes;
    Persistent<FunctionTemplate> request_tmpl;
    Persistent<FunctionTemplate> response_tmpl;
    Persistent<FunctionTemplate> evt_update_timer;
    Persistent<FunctionTemplate> evt_register_fd;
    Persistent<FunctionTemplate> evt_on_data;
} ngx_http_v8_loc_conf_t;

typedef struct {
    Persistent<Object> headers;
    Persistent<Value> data;
    function_t *next;
    ngx_uint_t done;
    ngx_uint_t header_sent;
    ngx_str_t redirect_uri;
    ngx_str_t redirect_args;
    brigade_t *in;
    brigade_t *out;
} ngx_http_v8_ctx_t;

class Ngxv8 {
    public:
        /* Utilities */
        static void HandleClean(void *data);
        static void MethodClean(void *data);
        static Local<FunctionTemplate> MakeRequestTemplate();
        static Local<FunctionTemplate> MakeResponseTemplate();
        static Local<Object> WrapRequest(ngx_http_v8_loc_conf_t *v8lcf,
                                         ngx_http_request_t *r);
        static Local<Object> WrapResponse(ngx_http_v8_loc_conf_t *v8lcf,
                                          ngx_http_request_t *r);
        static void* Unwrap(Handle<Object> obj, int field);
        static Handle<Value> Log(const Arguments& args);
        static void SendHeaders(ngx_http_request_t *r, ngx_http_v8_ctx_t *ctx, ngx_int_t rc);
        static void Flush(ngx_http_request_t *r, ngx_http_v8_ctx_t *ctx);

        /* Nginx Configuration */
        static void* CreateMainConf(ngx_conf_t *cf);
        static void* CreateLocConf(ngx_conf_t *cf);
        static char* MergeLocConf(ngx_conf_t *cf, void *parent, void *child);
        static char* V8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        static char* V8Com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        static char* V8Var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        static ngx_int_t InitProcess(ngx_cycle_t *cycle);

        /* Handlers */
        static ngx_int_t V8Handler(ngx_http_request_t *r);
        static void HandleRequest(ngx_http_request_t *r);
        static ngx_int_t CallHandler(ngx_http_request_t *r,
                                     ngx_http_v8_ctx_t *ctx,
                                     ngx_http_v8_loc_conf_t *v8lcf,
                                     Persistent<Function> fun);
        static void TimeoutHandler(ngx_http_request_t *r);
        static ngx_int_t VarGetter(ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v,
                                   uintptr_t data);

    private:
        static Handle<Value> ReadFile_(const char* filename);
        static int ExecuteScript_(const char* file);
        static ngx_http_v8_ctx_t* GetContext_(ngx_http_request_t *r);
};

class NginxRequest {
    public:
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> GetVariable(const Arguments& args);
        static Handle<Value> SetVariable(const Arguments& args);
        static Handle<Value> BindPool(const Arguments& args);
        static Handle<Value> Forward(const Arguments& args);
        static Handle<Value> Subrequest(const Arguments& args);
        static Handle<Value> IO(const Arguments& args);
        static Handle<Value> ReadBody(const Arguments& args);
        static Handle<Value> SendFile(const Arguments& args);
        static Handle<Value> SetTimeout(const Arguments& args);
        static Handle<Value> HandShake(const Arguments& args);
        static Handle<Value> GetUri(Local<String> name,
                                    const AccessorInfo& info);
        static Handle<Value> GetMethod(Local<String> name,
                                       const AccessorInfo& info);
        static Handle<Value> GetUserAgent(Local<String> name,
                                          const AccessorInfo& info);
        static Handle<Value> GetArgs(Local<String> name,
                                     const AccessorInfo& info);
        static Handle<Value> GetBodyBuffer(Local<String> name,
                                           const AccessorInfo& info);
        static Handle<Value> GetBodyFileOrBuffer(Local<String> name,
                                                 const AccessorInfo& info);
        static void SetBodyBuffer(Local<String> name,
                                  Local<Value> val,
                                  const AccessorInfo& info);
        static Handle<Value> GetHeader(Local<String> name,
                                       const AccessorInfo& info);
        static Handle<Value> GetRealPath(Local<String> name,
                                         const AccessorInfo& info);
    private:
        static void Bind(ngx_http_request_t *r, Persistent<Value> handle);
};

class NginxConnection {
    public:
        static Handle<Value> BindPool(const Arguments& args);
        static Handle<Value> Fd(Local<String> name, const AccessorInfo& info);
};

class NginxResponse {
    public:
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> Write(const Arguments& args);
        static Handle<Value> Dump(const Arguments& args);
        static Handle<Value> AddResponseHeader(const Arguments& args);
        static Handle<Value> GetRespContentType(Local<String> name,
                                                const AccessorInfo& info);
        static void SetRespContentType(Local<String> name,
                                       Local<Value> val,
                                       const AccessorInfo& info);
};

class NginxEvent {
    public:
        static void CloseIO(ngx_http_request_t *r);
        static void IOHandler(ngx_event_t *ev);
        static Handle<Value> UpdateTimer(const Arguments& args);
        static Handle<Value> RegisterFd(const Arguments& args);
        static Handle<Value> OnData(const Arguments& args);
};

void Ngxv8::HandleClean(void *data) {
    handle_t *h = static_cast<handle_t*>(data);
    h->handle.Dispose();
    h->handle.Clear();
}

void Ngxv8::MethodClean(void *data) {
    method_t *m = static_cast<method_t *>(data);
    HandleScope scope;
    Local<Value> v = m->fun->Call(m->recv, 0, NULL);
    m->recv.Dispose();
    m->fun.Dispose();
}


Local<FunctionTemplate> Ngxv8::MakeRequestTemplate() {
    HandleScope scope;
    Local<FunctionTemplate> reqTmpl = FunctionTemplate::New(NginxRequest::New);
    reqTmpl->SetClassName(String::NewSymbol("NginxRequest"));
    Local<ObjectTemplate> reqInstanceTmpl = reqTmpl->InstanceTemplate();
    reqInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> reqPrototypeTmpl = reqTmpl->PrototypeTemplate();
    reqInstanceTmpl->SetAccessor(String::NewSymbol("uri"),
                                 NginxRequest::GetUri);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("method"),
                                 NginxRequest::GetMethod);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("userAgent"),
                                 NginxRequest::GetUserAgent);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("args"),
                                 NginxRequest::GetArgs);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("body"),
                                 NginxRequest::GetBodyFileOrBuffer,
                                 NginxRequest::SetBodyBuffer);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("headers"),
                                 NginxRequest::GetHeader);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("realPath"),
                                 NginxRequest::GetRealPath);
    reqPrototypeTmpl->Set(String::NewSymbol("$"),
                          FunctionTemplate::New(NginxRequest::GetVariable));
    reqPrototypeTmpl->Set(String::NewSymbol("set"),
                          FunctionTemplate::New(NginxRequest::SetVariable));
    reqPrototypeTmpl->Set(String::NewSymbol("bind"),
                          FunctionTemplate::New(NginxRequest::BindPool));
    reqPrototypeTmpl->Set(String::NewSymbol("forward"),
                          FunctionTemplate::New(NginxRequest::Forward));
    reqPrototypeTmpl->Set(String::NewSymbol("subrequest"),
                          FunctionTemplate::New(NginxRequest::Subrequest));
    reqPrototypeTmpl->Set(String::NewSymbol("io"),
                          FunctionTemplate::New(NginxRequest::IO));
    reqPrototypeTmpl->Set(String::NewSymbol("readBody"),
                          FunctionTemplate::New(NginxRequest::ReadBody));
    reqPrototypeTmpl->Set(String::NewSymbol("sendfile"),
                          FunctionTemplate::New(NginxRequest::SendFile));
    reqPrototypeTmpl->Set(String::NewSymbol("setTimeout"),
                          FunctionTemplate::New(NginxRequest::SetTimeout));
    reqPrototypeTmpl->Set(String::NewSymbol("handshake"),
                          FunctionTemplate::New(NginxRequest::HandShake));
    return reqTmpl;
}

Local<FunctionTemplate> Ngxv8::MakeResponseTemplate() {
    HandleScope scope;
    Local<FunctionTemplate> respTmpl = FunctionTemplate::New(NginxResponse::New);
    respTmpl->SetClassName(String::NewSymbol("NginxResponse"));
    Local<ObjectTemplate> respInstanceTmpl = respTmpl->InstanceTemplate();
    respInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> respPrototypeTmpl = respTmpl->PrototypeTemplate();
    respInstanceTmpl->SetAccessor(String::NewSymbol("contentType"),
                                  NginxResponse::GetRespContentType,
                                  NginxResponse::SetRespContentType);
    respPrototypeTmpl->Set(String::NewSymbol("write"),
                           FunctionTemplate::New(NginxResponse::Write));
    respPrototypeTmpl->Set(String::NewSymbol("dump"),
                           FunctionTemplate::New(NginxResponse::Dump));
    respPrototypeTmpl->Set(String::NewSymbol("addHeader"),
                           FunctionTemplate::New(NginxResponse::AddResponseHeader));
    return respTmpl;
}

Local<Object> Ngxv8::WrapRequest(ngx_http_v8_loc_conf_t *v8lcf,
                                 ngx_http_request_t *r) {
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->request_tmpl->GetFunction()->NewInstance(1, argv);
    return scope.Close(result);
}

Local<Object> Ngxv8::WrapResponse(ngx_http_v8_loc_conf_t *v8lcf, ngx_http_request_t *r) {
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->response_tmpl->GetFunction()->NewInstance(1, argv);
    return scope.Close(result);
}

void* Ngxv8::Unwrap(Handle<Object> obj, int field) {
    return Handle<External>::Cast(obj->GetInternalField(field))->Value();
}

Handle<Value> Ngxv8::Log(const Arguments& args) {
    HandleScope scope;
    Local<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
    return Undefined();
}

void Ngxv8::SendHeaders(ngx_http_request_t *r, ngx_http_v8_ctx_t *ctx, ngx_int_t rc) {
    if (!ctx->header_sent) {
        r->headers_out.status = rc;
        if (r->headers_out.content_type.data == NULL) {
            r->headers_out.content_type.len = sizeof("text/html; charset=utf-8") - 1;
            r->headers_out.content_type.data = ptr_cast<u_char*>(
                const_cast<char*>("text/html; charset=utf-8"));
        }
        r->headers_out.content_length_n = ctx->out->size;

        ngx_http_send_header(r);
        ctx->header_sent = 1;
    }
}

void Ngxv8::Flush(ngx_http_request_t *r, ngx_http_v8_ctx_t *ctx) {
    if (ctx->out->head) {
        ngx_http_output_filter(r, ctx->out->head);
    }
}

// --- Request Method ---

Handle<Value> NginxRequest::New(const Arguments& args) {
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

Handle<Value> NginxRequest::GetVariable(const Arguments& args) {
    ngx_http_request_t          *r;
    size_t                      len;
    u_char                      *p, *lowcase;
    ngx_str_t                   var;
    ngx_uint_t                  hash;
    ngx_http_variable_value_t   *vv;

    HandleScope scope;
    String::AsciiValue name(args[0]);
    len = name.length();
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(args.This(), 0));
    lowcase = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    p = ptr_cast<u_char*>(*name);
    hash = ngx_hash_strlow(lowcase, p, len);
    var.len = len;
    var.data = lowcase;
    vv = ngx_http_get_variable(r, &var, hash, 1);
    //vv = ngx_http_get_variable(r, &var, hash);

    if (vv->not_found) {
        return Undefined();
    }
    return String::New(ptr_cast<const char*>(vv->data), vv->len);
}

Handle<Value> NginxRequest::SetVariable(const Arguments& args) {
    ngx_http_request_t          *r;
    size_t                      len;
    u_char                      *p, *lowcase;
    ngx_str_t                   var;
    ngx_uint_t                  hash;
    ngx_http_variable_value_t   *vv;

    HandleScope scope;
    String::AsciiValue name(args[0]);
    len = name.length();
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(args.This(), 0));
    lowcase = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    p = ptr_cast<u_char*>(*name);
    hash = ngx_hash_strlow(lowcase, p, len);
    var.len = len;
    var.data = lowcase;
    vv = ngx_http_get_variable(r, &var, hash, 1);
    //vv = ngx_http_get_variable(r, &var, hash);

    if (vv->not_found) {
        return False();
    }

    if (args[1]->IsArray()) {
        Local<Array> val = Local<Array>::Cast(args[1]);
        vv->len = val->Length();
        p = static_cast<u_char*>(ngx_pnalloc(r->pool, vv->len));
        for (uint64_t i = 0; i < vv->len; i++) {
            p[i] = val->Get(Number::New(i))->Int32Value();
        }
    } else {
        String::Utf8Value val(args[1]);
        vv->len = val.length();
        p = static_cast<u_char*>(ngx_pnalloc(r->pool, vv->len));
        ngx_memcpy(p, *val, vv->len);
    }

    vv->valid = 1;
    vv->no_cacheable = 0;
    vv->not_found = 0;
    vv->data = p;

    /*if (value) {
        vv->len = val.len;
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = val.data;
    }*/

    return True();
}

Handle<Value> NginxRequest::BindPool(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_pool_cleanup_t *c;
    method_t *m;

    r = static_cast<ngx_http_request_t *>(Ngxv8::Unwrap(args.This(), 0));
    m = static_cast<method_t *>(ngx_pcalloc(r->pool, sizeof(method_t)));

    HandleScope scope;
    Local<Function> f = Local<Function>::Cast(Local<Object>::Cast(args[0]));
    Local<Object> recv = Local<Object>::Cast(args[1]);
    m->fun = Persistent<Function>::New(f);
    m->recv = Persistent<Object>::New(recv);

    c = ngx_pool_cleanup_add(r->pool, 0);
    c->data = m;
    c->handler = &Ngxv8::MethodClean;

    return args[1];
}

Handle<Value> NginxRequest::Forward(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    unsigned int       i;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<String> uri = Local<String>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    ctx->redirect_uri.len = uri->Utf8Length();
    ctx->redirect_uri.data = static_cast<u_char*>(ngx_pnalloc(r->pool, ctx->redirect_uri.len));
    uri->WriteUtf8(ptr_cast<char*>(ctx->redirect_uri.data), ctx->redirect_uri.len);

    for (i = 0; i < ctx->redirect_uri.len; i++) {
        if (ctx->redirect_uri.data[i] == '?') {
            ctx->redirect_args.len = ctx->redirect_uri.len - (i + 1);
            ctx->redirect_args.data = &ctx->redirect_uri.data[i + 1];
            ctx->redirect_uri.len = i;
            return Integer::New(NGX_HTTP_OK);
        }
    }

    // TODO: NGX_AGAIN ?
    return Integer::New(NGX_OK);
}

Handle<Value> NginxRequest::Subrequest(const Arguments& args) {
    ngx_http_request_t *r, *sr;
    ngx_http_v8_ctx_t  *ctx;
    ngx_str_t          location;

    HandleScope scope;
    Local<Object> self = args.This();
    int rc = args[0]->Int32Value();
    Local<String> uri = Local<String>::Cast(args[1]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    location.len = uri->Utf8Length();
    location.data = static_cast<u_char*>(ngx_pnalloc(r->pool, location.len));
    uri->WriteUtf8(ptr_cast<char*>(location.data), location.len);

    Ngxv8::SendHeaders(r, ctx, rc);
    Ngxv8::Flush(r, ctx);
    ctx->done = 1;

    /*if (NGX_HTTP_OK <= rc && rc < NGX_HTTP_SPECIAL_RESPONSE) {
        r->keepalive = 1;
    }*/

    return Integer::New(ngx_http_subrequest(r, &location, NULL, &sr, NULL, 0));
}

void NginxEvent::CloseIO(ngx_http_request_t *r) {
    ngx_connection_t       *c;

    c = r->upstream->peer.connection;

    if (r->connection->write->timer_set) {
        ngx_del_timer(r->connection->write);
    }

    if (c) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
        if (c->read->prev) {
            ngx_delete_posted_event(c->read);
        }
        if (c->write->prev) {
            ngx_delete_posted_event(c->write);
        }
        c->read->closed = 1;
        c->write->closed = 1;
        ngx_free_connection(r->upstream->peer.connection);
    }
}

void NginxEvent::IOHandler(ngx_event_t *ev) {
    ngx_http_v8_loc_conf_t *v8lcf;
    ngx_http_request_t     *r;
    ngx_http_v8_ctx_t      *ctx;
    ngx_connection_t       *c;
    ngx_event_t            *aev;
    ngx_msec_t             key;

    c = static_cast<ngx_connection_t*>(ev->data);
    r = static_cast<ngx_http_request_t*>(c->data);
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    aev = c->write->active ? c->write : c->read;

    HandleScope scope;

    //printf("@@ IOHandler timedout=%d\n", ev->timedout);
    //printf("@@ ev=%d, read=%d, write=%d\n", (int)ev, (int)c->read, (int)c->write);
    //printf("@@ read=%d, %d\n", c->read->active, c->read->ready);
    //printf("@@ write=%d, %d\n", c->write->active, c->write->ready);
    Persistent<Object> data = Persistent<Object>::Cast(ctx->data);
    Local<Function> fun = Local<Function>::Cast(data->Get(String::NewSymbol("event_cb")));

    if (ev->timedout) {
        ev->timedout = 0;
        if (ev != aev) return;
    }

    key = ev->timer.key;

    Handle<Value> argv[2] = { Int32::New(c->fd), Boolean::New(aev->write) };
    int32_t running = fun->Call(v8lcf->context->Global(), 2, argv)->Int32Value();

    //printf("&\n");
    if (running > 0) {
        if (key == 0 && (key == ev->timer.key)) { // timer have not updated
            printf("@@ IOHandler wait a bit more\n");
            // wait a bit more
            if (aev->timer_set) {
                ngx_del_timer(aev);
            }
            ngx_add_timer(aev, 300);
        }
        return;
    }

    NginxEvent::CloseIO(r);

    //printf("last transfer done, kill timeout\n");
    Ngxv8::HandleRequest(r);
}

Handle<Value> NginxEvent::UpdateTimer(const Arguments& args) {
    ngx_http_request_t  *r;
    ngx_connection_t    *c;
    long                timeout_ms;

    HandleScope scope;
    timeout_ms = static_cast<long>(args[0]->IntegerValue());

    Local<Value> request = args.Callee()->Get(String::NewSymbol("request"));
    r = static_cast<ngx_http_request_t*>(
            Local<External>::Cast(request)->Value());
    
    c = r->upstream->peer.connection;
    
    if (r->connection->write->timer_set) {
        ngx_del_timer(r->connection->write);
    }
    if (!c) {
        //printf("timer update, %ld, peer=%d\n", timeout_ms, (int)c);
        ngx_add_timer(r->connection->write, timeout_ms);
        r->write_event_handler = Ngxv8::TimeoutHandler;
    } else {
        if (c->read->timer_set) {
            //printf("Upstream Delete Reading timeout\n");
            ngx_del_timer(c->read);
        }
        if (c->write->timer_set) {
            //printf("Upstream Delete Writing timeout\n");
            ngx_del_timer(c->write);
        }
        if (c->read->active) {
            //printf("Upstream Reading timeout=%ld\n", timeout_ms);
            ngx_add_timer(c->read, timeout_ms);
        } else if (c->write->active) {
            //printf("Upstream Writing timeout=%ld\n", timeout_ms);
            ngx_add_timer(c->write, timeout_ms);
        }
        //printf("++read %d, active=%d, timer_set=%d, timer=%d\n", (int)c->read, c->read->active, c->read->timer_set, c->read->timer.key);
        //printf("++write %d active=%d, timer_set=%d, timer=%d\n", (int)c->write, c->write->active, c->write->timer_set, c->write->timer.key);
    }

    return Undefined();
}

Handle<Value> NginxEvent::RegisterFd(const Arguments& args) {
    int32_t             fd, what;
    ngx_http_request_t  *r;
    ngx_connection_t    *c;
    ngx_http_v8_ctx_t   *ctx;

    HandleScope scope;

    Local<Value> request = args.Callee()->Get(String::NewSymbol("request"));
    r = static_cast<ngx_http_request_t*>(
            Local<External>::Cast(request)->Value());

    fd = args[0]->Int32Value();
    what = args[1]->Int32Value();
    //printf("RegisterFd %d %d\n", fd, what);

    //printf("Peer connection=%d\n", (int)r->upstream->peer.connection);

    c = r->upstream->peer.connection;

    //printf("@\n");
    if (!c) {
        c = ngx_get_connection(fd, r->connection->log);
        printf("%d\n", ngx_cycle->free_connection_n);
        if (!c) {
            NginxEvent::CloseIO(r);
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return Undefined();
        }

        c->data = r;

        // ???
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        c->read->handler = NginxEvent::IOHandler;
        c->write->handler = NginxEvent::IOHandler;

        //printf("################\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        switch (what) {
            case 0:  // read
                ngx_handle_read_event(c->read, 0);
                break;
            case 1:  // write
                ngx_handle_write_event(c->write, 0);
                break;
        }

        r->upstream->peer.connection = c;

        //printf("Connected c=%d\n", (int)c);

        //printf("##------------##\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        //printf("################\n");

        //printf("#\n");
        return Undefined();
    } else if (what != -1) {
        //printf("################\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, 0);
            c->read->ready = 0;
        } else if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
            c->write->ready = 0;
        }

        //printf("##------------##\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        switch (what) {
            case 0: // read
                ngx_handle_read_event(c->read, 0);
                break;
            case 1: // write
                ngx_handle_write_event(c->write, 0);
                break;
        }
        //printf("##------------##\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        //printf("################\n");
        //printf("%%\n");
        return Undefined();
    }

    if (what == -1) {
        //printf("################\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            c->read->ready = 0;
        } else if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
            c->write->ready = 0;
        }

        ctx = static_cast<ngx_http_v8_ctx_t*>(
            ngx_http_get_module_ctx(r, ngx_http_v8_module));
        //ctx->done = 1;

        //printf("##------------##\n");
        //printf("## read =%d, %d ##\n", c->read->active, c->read->ready);
        //printf("## write=%d, %d ##\n", c->write->active, c->write->ready);
        //printf("################\n");
        //printf("Disconnect\n");
    }

    return Undefined();
}

Handle<Value> NginxEvent::OnData(const Arguments& args) {
    ngx_http_request_t  *r;
    ngx_http_v8_ctx_t   *ctx;
    u_char              *data, *p;
    ngx_buf_t           *b;
    ngx_chain_t         *out;
    brigade_t           *bri;
    long                len;

    HandleScope scope;
    Local<Value> request = args.Callee()->Get(String::NewSymbol("request"));
    r = static_cast<ngx_http_request_t*>(
            Local<External>::Cast(request)->Value());
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    data = static_cast<u_char*>(Local<External>::Cast(args[0])->Value());
    len = static_cast<long>(args[1]->IntegerValue());

    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(p, data, len);

    if (ctx->in == NULL) {
        ctx->in = static_cast<brigade_t*>(ngx_pcalloc(r->pool, sizeof(brigade_t)));
    }

    bri = ctx->in;
    bri->size += len;

    b = static_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Failed to allocate response buffer.");
    }
    b->memory = 1;
    b->pos = p;
    b->last = p + len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    //printf("Buffering...\n");

    return Undefined();
}

Handle<Value> NginxRequest::IO(const Arguments& args) {
    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_request_t      *r;
    ngx_http_v8_ctx_t       *ctx;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<Function> init = Local<Function>::Cast(args[0]);
    Local<Function> post_fun = Local<Function>::Cast(args[1]);
    
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    NginxRequest::Bind(r, ctx->next->fun);

    r->upstream = static_cast<ngx_http_upstream_t*>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t)));

    Local<External> request = External::New(r);
    Local<Function> update_timer = v8lcf->evt_update_timer->GetFunction();
    Local<Function> register_fd = v8lcf->evt_register_fd->GetFunction();
    Local<Function> on_data = v8lcf->evt_on_data->GetFunction();

    update_timer->Set(String::NewSymbol("request"), request);
    register_fd->Set(String::NewSymbol("request"), request);
    on_data->Set(String::NewSymbol("request"), request);

    Handle<Value> argv[3] = {
        update_timer,
        register_fd,
        on_data
    };
    Local<Object> cbs = Local<Object>::Cast(init->Call(v8lcf->context->Global(), 3, argv));
    ctx->data = Persistent<Object>::New(cbs);
    NginxRequest::Bind(r, ctx->data);

    return Integer::New(NGX_AGAIN);
}

Handle<Value> NginxRequest::ReadBody(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    //ctx->next->fun.MakeWeak(NULL, Ngxv8::DisposeHandle);
    NginxRequest::Bind(r, ctx->next->fun);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    return Integer::New(ngx_http_read_client_request_body(r, Ngxv8::HandleRequest));
}

Handle<Value> NginxRequest::SendFile(const Arguments& args) {
    ngx_http_request_t          *r;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_v8_ctx_t           *ctx;
    ngx_buf_t                   *b;
    ngx_str_t                   path;
    off_t                       offset;
    size_t                      bytes;
    ngx_open_file_info_t        of;
    brigade_t                   *bri;
    ngx_chain_t                 *out;

    HandleScope scope;
    Local<Object> self = args.This();
    
    String::Utf8Value filename(args[0]);
    offset = args[1]->Int32Value();
    bytes = args[2]->Int32Value();

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    clcf = static_cast<ngx_http_core_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_core_module));

    path.len = filename.length();
    path.data = static_cast<u_char*>(ngx_pnalloc(r->pool, path.len + 1));
    ngx_cpystrn(path.data, ptr_cast<u_char*>(*filename), path.len + 1);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK) {   
        if (of.err == 0) {
            return False();;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                "%s \"%s\" failed", of.failed, *filename);
        return False();
    }

    if (offset == -1) {
        offset = 0;
    }

    if (bytes == 0) {
        bytes = of.size - offset;
    }

    b = static_cast<ngx_buf_t*>(ngx_calloc_buf(r->pool));
    b->file = static_cast<ngx_file_t*>(ngx_pcalloc(r->pool, sizeof(ngx_file_t)));

    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    b->file_pos = offset;
    b->file_last = offset + bytes;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = r->connection->log;
    b->file->directio = of.is_directio;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    bri = ctx->out;
    bri->size += bytes;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    return True();
}

Handle<Value> NginxRequest::SetTimeout(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_msec_t         timeout;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);
    timeout = args[1]->Int32Value();;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    //ctx->next->fun.MakeWeak(NULL, Ngxv8::DisposeHandle);
    NginxRequest::Bind(r, ctx->next->fun);

    ngx_add_timer(r->connection->write, timeout);

    r->write_event_handler = Ngxv8::TimeoutHandler;

    return Integer::New(r->connection->write->timer.key);
}

Handle<Value> NginxRequest::HandShake(const Arguments& args) {
    ngx_http_request_t      *r;
    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_v8_ctx_t       *ctx;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<Function> recv_fun = Local<Function>::Cast(args[0]);
    Local<Function> conn_fun = Local<Function>::Cast(args[1]);
    Local<Function> disconn_fun = Local<Function>::Cast(args[2]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));

    ctx->next->fun = Persistent<Function>::New(recv_fun);
    //ctx->next->fun.MakeWeak(NULL, Ngxv8::DisposeHandle);
    NginxRequest::Bind(r, ctx->next->fun);

    r->headers_out.status = 101;
    r->headers_out.status_line.len = sizeof("101 Web Socket Protocol Handshake") - 1;
    r->headers_out.status_line.data = ptr_cast<u_char*>(
            const_cast<char*>("101 Web Socket Protocol Handshake"));
    ngx_http_send_header(r);
    ctx->header_sent = 1;

    if (args[1]->IsFunction()) {
        conn_fun->Call(v8lcf->context->Global(), 0, NULL);
    }

    return Integer::New(NGX_AGAIN);
}

// --- Request Properties ---

Handle<Value> NginxRequest::GetUri(Local<String> name,
                                   const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->uri.data), r->uri.len);
}

Handle<Value> NginxRequest::GetMethod(Local<String> name,
                                      const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->method_name.data),
                       r->method_name.len);
}

Handle<Value> NginxRequest::GetUserAgent(Local<String> name,
                                         const AccessorInfo& info) {
    ngx_http_request_t *r;
    ngx_str_t          ua;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    ua = r->headers_in.user_agent->value;

    return String::New(ptr_cast<const char*>(ua.data), ua.len);
}

Handle<Value> NginxRequest::GetArgs(Local<String> name,
                                    const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->args.data), r->args.len);
}

Handle<Value> NginxRequest::GetBodyBuffer(Local<String> name,
                                          const AccessorInfo& info) {
    ngx_http_request_t *r;
    size_t             len;

    r = static_cast<ngx_http_request_t *>(Ngxv8::Unwrap(info.Holder(), 0));
    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL) {
        return Undefined();
    }

    len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos;

    if (len == 0) {
        return Undefined();
    }

    return String::New(ptr_cast<const char*>(r->request_body->bufs->buf->pos),
                       len);
}

Handle<Value> NginxRequest::GetBodyFileOrBuffer(Local<String> name,
                                                const AccessorInfo& info) {
    ngx_http_request_t  *r;
    char                *data;
    int                 fd;
    off_t               len;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    if (r->request_body == NULL
        || r->request_body->temp_file == NULL) {
        return NginxRequest::GetBodyBuffer(name, info);
    }

    fd = r->request_body->temp_file->file.fd;
    len = r->headers_in.content_length_n;

    data = static_cast<char*>(mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0));

    HandleScope scope;
    Local<String> b = String::New(data, len);
    munmap(data, len);

    return scope.Close(b);
}

void NginxRequest::SetBodyBuffer(Local<String> name,
                                 Local<Value> val,
                                 const AccessorInfo& info) {
    printf("---\n");
    ngx_http_request_t  *r;
    u_char             *p;
    int                len;
    
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);
    printf("---1\n");

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);
    printf("---2\n");

    //printf("%d\n", r->request_body == NULL);
    r->request_body->bufs->buf->pos = p;
    r->request_body->bufs->buf->last = p + len;
    r->request_body->temp_file = NULL;
    printf("---3\n");
}

Handle<Value> NginxRequest::GetHeader(Local<String> name,
                                      const AccessorInfo& info) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_list_part_t    *part;
    ngx_table_elt_t    *h;
    unsigned int       i;

    HandleScope scope;
    Local<Object> result = Object::New();

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (!ctx->headers.IsEmpty()) {
        return scope.Close(ctx->headers);
    }

    part = &r->headers_in.headers.part;
    h = static_cast<ngx_table_elt_t*>(part->elts);

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = static_cast<ngx_table_elt_t*>(part->elts);
            i = 0;
        }

        result->Set(String::New(ptr_cast<const char*>(h[i].key.data), h[i].key.len),
                    String::New(ptr_cast<const char*>(h[i].value.data), h[i].value.len));
    }

    ctx->headers = Persistent<Object>::New(result);
    //ctx->headers.MakeWeak(NULL, Ngxv8::DisposeHandle);
    NginxRequest::Bind(r, ctx->headers);

    return scope.Close(result);
}

Handle<Value> NginxRequest::GetRealPath(Local<String> name,
                                        const AccessorInfo& info) {
    ngx_http_request_t  *r;
    u_char              *last;
    size_t              root;
    ngx_str_t           path;

    HandleScope scope;
    Local<Object> self = info.Holder();
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    path.len = last - path.data;

    return String::New(ptr_cast<const char*>(path.data), path.len);
}

void NginxRequest::Bind(ngx_http_request_t *r, Persistent<Value> handle) {
    ngx_pool_cleanup_t *c;
    handle_t           *h;

    h = static_cast<handle_t *>(ngx_pcalloc(r->pool, sizeof(handle_t)));
    h->handle = handle;

    c = ngx_pool_cleanup_add(r->pool, 0);
    c->data = h;
    c->handler = Ngxv8::HandleClean;
}

Handle<Value> NginxResponse::New(const Arguments& args) {
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

Handle<Value> NginxResponse::Write(const Arguments& args) {
    ngx_chain_t         *out;
    ngx_http_request_t  *r;
    ngx_http_v8_ctx_t   *ctx;
    ngx_buf_t           *b;
    brigade_t           *bri;
    size_t              len;
    u_char              *p;

    HandleScope scope;
    Local<Object> self = args.This();

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    String::Utf8Value v(args[0]);
    len = v.length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(p, *v, len);

    bri = ctx->out;
    bri->size += len;

    b = static_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Failed to allocate response buffer.");
    }
    b->memory = 1;
    b->pos = p;
    b->last = p + len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    return Undefined();
}

Handle<Value> NginxResponse::Dump(const Arguments& args) {
    ngx_chain_t         *out;
    ngx_http_request_t  *r;
    ngx_http_v8_ctx_t   *ctx;
    ngx_buf_t           *b;
    brigade_t           *bri;
    size_t              len;
    u_char              *p;

    HandleScope scope;
    Local<Object> self = args.This();

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (args[0]->IsArray()) {
        Local<Array> a = Local<Array>::Cast(args[0]);
        len = a->Length();
        if (len == 0) {
            return Undefined();
        }
        p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
        for (unsigned int i = 0; i < len; i++) {
            p[i] = a->Get(Number::New(i))->Int32Value();
        }
    } else {
        String::Utf8Value v(args[0]);
        len = v.length();
        p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
        ngx_memcpy(p, *v, len);
    }

    bri = ctx->out;
    bri->size += len;

    b = static_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Failed to allocate response buffer.");
    }
    b->memory = 1;
    b->pos = p;
    b->last = p + len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    return Undefined();
}

Handle<Value> NginxResponse::AddResponseHeader(const Arguments& args) {
    ngx_http_request_t  *r;
    ngx_table_elt_t     *header;
    u_char              *contentLength;
    size_t              len;

    HandleScope scope;
    Local<Object> self = args.This();
    String::AsciiValue key(args[0]);
    String::AsciiValue value(args[1]);
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    header = static_cast<ngx_table_elt_t*>(ngx_list_push(&r->headers_out.headers));
    header->hash = 1;

    len = key.length();
    header->key.len = len;
    header->key.data = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(header->key.data, *key, len);

    len = value.length();
    header->value.len = len;
    header->value.data = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(header->value.data, *value, len);

    contentLength = ptr_cast<u_char*>(const_cast<char*>("Content-Length"));
    if (header->key.len == sizeof("Content-Length") - 1
        && ngx_strncasecmp(header->key.data, contentLength,
                           sizeof("Content-Length") - 1) == 0)
    {
        r->headers_out.content_length_n = static_cast<off_t>(atoi(*value));
        r->headers_out.content_length = header;
    }
    return Undefined();
}

// --- Response Properties ---

Handle<Value> NginxResponse::GetRespContentType(Local<String> name,
                                                const AccessorInfo& info) {
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    return String::New(ptr_cast<const char*>(r->headers_out.content_type.data),
        r->headers_out.content_type.len);
}

void NginxResponse::SetRespContentType(Local<String> name,
                                       Local<Value> val,
                                       const AccessorInfo& info) {
    ngx_http_request_t *r;
    u_char             *p;
    int                len;
   
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);

    r->headers_out.content_type.data = p;
    r->headers_out.content_type.len = len;
}

static ngx_command_t  ngx_http_v8_commands[] = {

    { ngx_string("v8"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        Ngxv8::V8,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("v8com"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        Ngxv8::V8Com,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("v8agent"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_v8_main_conf_t, agent_port),
        NULL },

    { ngx_string("v8var"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        Ngxv8::V8Var,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_v8_module_ctx = {
    NULL,                                /* preconfiguration */
    NULL,                                /* postconfiguration */

    Ngxv8::CreateMainConf,               /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    Ngxv8::CreateLocConf,                /* create location configuration */
    Ngxv8::MergeLocConf                  /* merge location configuration */

};

ngx_module_t  ngx_http_v8_module = {
    NGX_MODULE_V1,
    &ngx_http_v8_module_ctx,       /* module context */
    ngx_http_v8_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    Ngxv8::InitProcess,            /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

void* Ngxv8::CreateMainConf(ngx_conf_t *cf) {
    ngx_http_v8_main_conf_t *conf;

    conf = static_cast<ngx_http_v8_main_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_main_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->agent_port = NGX_CONF_UNSET_UINT;

    return conf;
}

void* Ngxv8::CreateLocConf(ngx_conf_t *cf) {
    ngx_http_v8_loc_conf_t *conf;

    conf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_loc_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

char* Ngxv8::MergeLocConf(ngx_conf_t *cf, void *parent, void *child) {
    return NGX_CONF_OK;
}

char* Ngxv8::V8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_v8_loc_conf_t      *v8lcf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t                   *value;
    const char                  *filename;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(conf);
    value = static_cast<ngx_str_t*>(cf->args->elts);

    clcf = static_cast<ngx_http_core_loc_conf_t *>(
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module));
    clcf->handler = Ngxv8::V8Handler;

    HandleScope scope;
    if (v8lcf->context.IsEmpty()) {
        //V8::SetFlagsFromString("--expose_debug_as debug", strlen("--expose_debug_as debug"));
        Local<ObjectTemplate> global = ObjectTemplate::New();
        Local<ObjectTemplate> components = ObjectTemplate::New();
        global->Set(String::NewSymbol("log"), FunctionTemplate::New(Ngxv8::Log));
        if (v8lcf->classes.IsEmpty()) {
            v8lcf->classes = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
        }
        components->Set(String::NewSymbol("classes"), v8lcf->classes);
        global->Set(String::NewSymbol("Components"), components);

        v8lcf->request_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeRequestTemplate());
        global->Set(String::NewSymbol("NginxRequest"), v8lcf->request_tmpl);

        v8lcf->response_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeResponseTemplate());
        global->Set(String::NewSymbol("NginxResponse"), v8lcf->response_tmpl);

        v8lcf->evt_update_timer = Persistent<FunctionTemplate>::New(
                FunctionTemplate::New(NginxEvent::UpdateTimer));
        v8lcf->evt_register_fd = Persistent<FunctionTemplate>::New(
                FunctionTemplate::New(NginxEvent::RegisterFd));
        v8lcf->evt_on_data = Persistent<FunctionTemplate>::New(
                FunctionTemplate::New(NginxEvent::OnData));

        const char *extensionNames[] = { "v8/gc" };
        ExtensionConfiguration extensions(sizeof(extensionNames)/sizeof(extensionNames[0]),
                                          extensionNames);
        //v8lcf->context = Context::New(NULL, global);
        v8lcf->context = Context::New(&extensions, global);
    }

    Context::Scope context_scope(v8lcf->context);
    filename = ptr_cast<const char*>(value[1].data);
    if (Ngxv8::ExecuteScript_(filename) == -1) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    if (v8lcf->process.IsEmpty() &&
        v8lcf->context->Global()->Has(String::NewSymbol("process"))) {
        Local<Value> process_val = v8lcf->context->Global()->Get(String::NewSymbol("process"));
        Local<Function> process_fun = Local<Function>::Cast(process_val);
        v8lcf->process = Persistent<Function>::New(process_fun);
    }

    return NGX_CONF_OK;
}

char* Ngxv8::V8Com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_v8_loc_conf_t     *v8lcf;
    ngx_str_t                  *value;
    void                       *handle;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(conf);
    value = static_cast<ngx_str_t*>(cf->args->elts);

    HandleScope scope;

    if (v8lcf->classes.IsEmpty()) {
        Handle<ObjectTemplate> classes = ObjectTemplate::New();
        v8lcf->classes = Persistent<ObjectTemplate>::New(classes);
    }

    Handle<String> name = String::New(ptr_cast<const char*>(value[1].data));
    if ((handle = dlopen(ptr_cast<const char*>(value[2].data), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: %s: %s\n", dlerror(), value[2].data);
        return static_cast<char*>(NGX_CONF_ERROR);
    }
    Handle<Template>(*createObject)();

    createObject = reinterpret_cast<Handle<Template> (*)()>(dlsym(handle, "createObject"));
    v8lcf->classes->Set(name, createObject());
    //dlclose(handle);

    return NGX_CONF_OK;
}

char* Ngxv8::V8Var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_int_t                   index;
    ngx_str_t                  *value;
    ngx_http_variable_t        *v;

    value = static_cast<ngx_str_t*>(cf->args->elts);

    if (value[1].data[0] != '$') {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    v->get_handler = Ngxv8::VarGetter;

    return NGX_CONF_OK;
}

ngx_int_t Ngxv8::InitProcess(ngx_cycle_t *cycle)
{
    ngx_core_conf_t         *ccf;
    ngx_http_v8_main_conf_t *v8mcf;

    v8mcf = static_cast<ngx_http_v8_main_conf_t*>(
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_v8_module));

    if (v8mcf->agent_port == NGX_CONF_UNSET_UINT) {
        return NGX_OK;
    }

    ccf = ptr_cast<ngx_core_conf_t*>(ngx_get_conf(cycle->conf_ctx, ngx_core_module));

    if (ccf->worker_processes > 1) {
        printf("v8agent could be active only when worker_processes = 1.\n");
        return NGX_ERROR;
    }

    Debug::EnableAgent("ngxv8", v8mcf->agent_port);
    printf("v8 debug agent is started: 127.0.0.1:%d\n", v8mcf->agent_port);
    
    return NGX_OK;
}

ngx_int_t Ngxv8::V8Handler(ngx_http_request_t *r) {
    Ngxv8::HandleRequest(r);
    return NGX_DONE;
}

void Ngxv8::HandleRequest(ngx_http_request_t *r) {
    ngx_int_t               rc;
    ngx_str_t               uri, args;
    ngx_http_v8_ctx_t       *ctx;
    ngx_http_v8_loc_conf_t  *v8lcf;
    Persistent<Function>    fun;

    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (ctx == NULL) {
        ctx = static_cast<ngx_http_v8_ctx_t*>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_v8_ctx_t)));
        ctx->out = static_cast<brigade_t*>(ngx_palloc(r->pool, sizeof(brigade_t)));
        ctx->out->size = 0;
        ctx->out->head = ctx->out->tail = NULL;
        ngx_http_set_ctx(r, ctx, ngx_http_v8_module);
    }

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));

    if (ctx->next == NULL) {
        fun = v8lcf->process;
    } else {
        fun = ctx->next->fun;
        ctx->next = NULL;
    }
    
    ngx_http_clean_header(r);

    rc = Ngxv8::CallHandler(r, ctx, v8lcf, fun);

    if (rc == NGX_DONE) {
        return;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;
        args = ctx->redirect_args;
    } else {
        uri.len = 0;
    }

    ctx->redirect_uri.len = 0;

    /*if (rc > 600) {
        rc = NGX_OK;
    }*/

    if (rc == NGX_AGAIN || ctx->done || ctx->next) {
        return;
    }

    if (uri.len) {
        ngx_http_internal_redirect(r, &uri, &args);
        return;
    }

    if (rc == NGX_OK) {
        rc = NGX_HTTP_OK;
    }

    if ((rc != NGX_OK) && !(NGX_HTTP_OK <= rc && rc < NGX_HTTP_SPECIAL_RESPONSE)) {
        r->keepalive = 0;
    }

    if (r->headers_in.range) {
        r->allow_ranges = 1;
    }

    Ngxv8::SendHeaders(r, ctx, rc);
    Ngxv8::Flush(r, ctx);

    ngx_http_send_special(r, NGX_HTTP_LAST);

    ctx->done = 1;

    ngx_http_finalize_request(r, rc);
}

ngx_int_t Ngxv8::CallHandler(ngx_http_request_t *r,
                             ngx_http_v8_ctx_t *ctx,
                             ngx_http_v8_loc_conf_t *v8lcf,
                             Persistent<Function> fun) {
    ngx_connection_t *c;
    ngx_chain_t      *cl;
    char *inp, *inpp;
    long size;

    c = r->connection;

    Context::Scope context_scope(v8lcf->context);
    HandleScope scope;

    Local<Object> request_obj = Ngxv8::WrapRequest(v8lcf, r);
    Local<Object> response_obj = Ngxv8::WrapResponse(v8lcf, r);
    Handle<Value> in = Undefined();

    if (ctx->in && ctx->in->size > 0) {
        cl = ctx->in->head;
        inp = static_cast<char*>(ngx_pnalloc(r->pool, ctx->in->size));
        inpp = inp;

        while (true) {
            size = ngx_buf_size(cl->buf);
            ngx_memcpy(inpp, cl->buf->pos, size);
            inpp += size;

            if (cl->next == NULL || cl->buf->last_buf) {
                break;
            }
            cl = cl->next;
        }
        in = String::New(inp, ctx->in->size);
    }

    Handle<Value> argv[3] = { request_obj, response_obj, in };

    TryCatch trycatch;
    Handle<Value> result = fun->Call(v8lcf->context->Global(), 3, argv);
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        fprintf(ngx_daemonized ? stderr : stdout, "call: %s\n", *st_str);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (c->destroyed) {
        return NGX_DONE;
    }

    if (result->IsUndefined()) {
        return NGX_OK;
    }

    return static_cast<ngx_int_t>(result->Int32Value());
}

void Ngxv8::TimeoutHandler(ngx_http_request_t *r) {
    ngx_http_v8_loc_conf_t *v8lcf;
    ngx_http_v8_ctx_t      *ctx;
    ngx_event_t            *wev;

    wev = r->connection->write;

    if (!wev->timedout) {
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    wev->timedout = 0;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    HandleScope scope;
    Persistent<Object> data = Persistent<Object>::Cast(ctx->data);

    /*if (data.IsEmpty()) {
        //printf("Timeout Handler: calling HandleRequest\n");
        Ngxv8::HandleRequest(r);
        return;
    }*/
   
    Local<Function> fun = Local<Function>::Cast(
            data->Get(String::NewSymbol("timeout_cb")));

    if (!fun.IsEmpty() && fun->IsFunction()) {
        //printf("Timeout Handler: calling Func\n");
        int32_t running = fun->Call(v8lcf->context->Global(), 0, NULL)->Int32Value();
        //printf("=\n");
        if (running <= 0) {
            //printf("Timeout Handler: calling HandleRequest\n");
            NginxEvent::CloseIO(r);
            Ngxv8::HandleRequest(r);
        } else {
            //printf(":::::%d\n", (int)r->upstream->peer.connection);
            //printf("Timed out but STILL RUNNING: %d\n", running);
            //printf("@@ TimeoutHandler wait a bit more\n");
            ngx_add_timer(r->connection->write, 100);
        }
        return;
    }

    // never reach?
    printf("Timeout Handler: calling HandleRequest\n");
    NginxEvent::CloseIO(r);
    Ngxv8::HandleRequest(r);
}

ngx_int_t Ngxv8::VarGetter(ngx_http_request_t *r,
                    ngx_http_variable_value_t *v,
                    uintptr_t data) {
    return NGX_OK;
}

Handle<Value> Ngxv8::ReadFile_(const char* filename) {
    int fd;
    struct stat sb;
    unsigned char *bytes;

    HandleScope scope;
    
    if ((fd = open(filename, O_RDONLY)) == -1) {
        fprintf(stderr, "open: %s: %s\n", strerror(errno), filename);
        return Null();
    }

    fstat(fd, &sb);

    bytes = static_cast<unsigned char*>(mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));

    if (close(fd) != 0) {
        fprintf(stderr, "close: %s: %s\n", strerror(errno), filename);
        return Null();
    }

    Local<String> result = String::New(ptr_cast<const char*>(bytes), sb.st_size);
    munmap(bytes, sb.st_size);

    return scope.Close(result);
}

int Ngxv8::ExecuteScript_(const char* file) {
    HandleScope scope;

    Handle<Value> source = Ngxv8::ReadFile_(file);
    if (!source->IsString() || Handle<String>::Cast(source)->Length() == 0) {
        return -1;
    }

    Local<String> filename = String::New(file);
    Local<Script> script = Script::Compile(Handle<String>::Cast(source), filename);

    TryCatch trycatch;
    Local<Value> result = script->Run();
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        fprintf(stderr, "run: %s\n", *st_str);
        return -1;
    }

    scope.Close(result);
    return 0;
}

ngx_http_v8_ctx_t* Ngxv8::GetContext_(ngx_http_request_t *r) {
    ngx_http_v8_ctx_t *ctx;

    ctx = static_cast<ngx_http_v8_ctx_t*>(
            ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (ctx == NULL) {
        ctx = static_cast<ngx_http_v8_ctx_t*>(
                ngx_pcalloc(r->pool, sizeof(ngx_http_v8_ctx_t)));
        ctx->in = NULL;
        ctx->out = static_cast<brigade_t*>(ngx_palloc(r->pool, sizeof(brigade_t)));
        ctx->out->size = 0;
        ctx->out->head = ctx->out->tail = NULL;
        ngx_http_set_ctx(r, ctx, ngx_http_v8_module);
    }

    return ctx;
}
