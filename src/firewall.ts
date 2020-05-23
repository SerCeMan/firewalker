import {
    initWirefilter,
    wirefilter_externally_allocated_byte_arr_t,
    wirefilter_externally_allocated_str_t,
    WIREFILTER_TYPE_BOOL,
    WIREFILTER_TYPE_BYTES,
    WIREFILTER_TYPE_INT,
    WIREFILTER_TYPE_IP
} from "./wirefilter";
import {Request} from "node-fetch";
import {Address4, Address6} from "ip-address";
import * as path from "path";

function wirefilterString(s: string) {
    let str = new wirefilter_externally_allocated_str_t();
    str.data = s;
    str.length = s.length;
    return str;
}

function wirefilterByteArray(s: string) {
    let str = new wirefilter_externally_allocated_byte_arr_t();
    str.data = Buffer.alloc(s.length, s);
    str.length = s.length;
    return str;
}

function addString(wirefilter: any, scheme: any, name: string): void {
    wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        WIREFILTER_TYPE_BYTES
    );
}

function addIPaddr(wirefilter: any, scheme: any, name: string): void {
    wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        WIREFILTER_TYPE_IP
    );
}

function addNumber(wirefilter: any, scheme: any, name: string): void {
    wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        WIREFILTER_TYPE_INT
    );
}

function addBoolen(wirefilter: any, scheme: any, name: string): void {
    wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        WIREFILTER_TYPE_BOOL
    );
}

export class Firewall {
    private readonly wirefilter: any;
    private readonly scheme: any;

    constructor() {
        let libPath: string;
        switch (process.platform) {
            case "darwin":
                libPath = path.join(__dirname, '..', 'lib', 'libwirefilter_ffi.dylib');
                break;
            case "linux":
                libPath = path.join(__dirname, '..', 'lib', 'libwirefilter_ffi.so');
                break
            default:
                throw new Error(`Unsupported platform: ${process.platform}`)
        }
        const wirefilter = initWirefilter(libPath)
        const scheme = wirefilter.wirefilter_create_scheme();
        // see https://developers.cloudflare.com/firewall/cf-firewall-language/
        // Standard fields
        addString(wirefilter, scheme, "http.cookie")
        addString(wirefilter, scheme, "http.host")
        addString(wirefilter, scheme, "http.referer")
        addString(wirefilter, scheme, "http.request.full_uri")
        addString(wirefilter, scheme, "http.request.method")
        addString(wirefilter, scheme, "http.request.uri")
        addString(wirefilter, scheme, "http.request.uri.path")
        addString(wirefilter, scheme, "http.request.uri.query")
        addString(wirefilter, scheme, "http.user_agent")
        addNumber(wirefilter, scheme, "http.request.version")
        addString(wirefilter, scheme, "http.x_forwarded_for")
        addIPaddr(wirefilter, scheme, "ip.src")
        addNumber(wirefilter, scheme, "ip.geoip.asnum")
        addString(wirefilter, scheme, "ip.geoip.continent")
        addString(wirefilter, scheme, "ip.geoip.country")
        addString(wirefilter, scheme, "ip.geoip.subdivision_1_iso_code")
        addString(wirefilter, scheme, "ip.geoip.subdivision_2_iso_code")
        addBoolen(wirefilter, scheme, "ip.geoip.is_in_european_union")
        addBoolen(wirefilter, scheme, "ssl")
        // Argument and value fields for URIs
        // ...
        // Header fields
        // ...
        // Body fields
        // ...
        // Dynamic fields
        addBoolen(wirefilter, scheme, "cf.bot_management.verified_bot")
        addNumber(wirefilter, scheme, "cf.threat_score")
        addNumber(wirefilter, scheme, "cf.edge.server_port")
        addBoolen(wirefilter, scheme, "cf.client.bot")
        addNumber(wirefilter, scheme, "cf.client_trust_score")
        this.wirefilter = wirefilter;
        this.scheme = scheme;
    }

    createFirewallRule(rule: string): FirewallRule {
        return new FirewallRule(this.wirefilter, this.scheme, rule)
    }
}

// Firewall rules

export class FirewallRule {
    private readonly filter: any;

    constructor(
        private readonly wirefilter: any, //
        private readonly scheme: any, //
        private readonly rule: string, //
    ) {
        const parsingResult = wirefilter.wirefilter_parse_filter(
            scheme,
            wirefilterString(rule)
        );
        if (parsingResult.ok.success != 1) {
            throw Error(`Can't parse the rule: ${parsingResult.err.msg.data}`)
        }
        const ast = parsingResult.ok.ast;
        let compilingResult = wirefilter.wirefilter_compile_filter(ast);
        if (compilingResult.ok.success != 1) {
            throw Error(`Can't compile the rule: ${compilingResult.err.msg.data}`)
        }
        this.filter = compilingResult.ok.filter;
    }

    match(req: Request): boolean {
        const wirefilter = this.wirefilter;
        const exec_ctx = wirefilter.wirefilter_create_execution_context(this.scheme);
        const url = new URL(req.url);
        this.addStringToCtx(exec_ctx, "http.cookie", req.headers.get('Cookie') || '');
        this.addStringToCtx(exec_ctx, "http.host", url.hostname);
        this.addStringToCtx(exec_ctx, "http.referer", req.headers.get('Referer') || '');
        this.addStringToCtx(exec_ctx, "http.request.full_uri", req.url);
        this.addStringToCtx(exec_ctx, "http.request.method", req.method);
        this.addStringToCtx(exec_ctx, "http.request.uri", `${url.pathname}${url.search}`);
        this.addStringToCtx(exec_ctx, "http.request.uri.path", url.pathname);
        this.addStringToCtx(exec_ctx, "http.request.uri.query", url.searchParams.toString());
        this.addStringToCtx(exec_ctx, "http.user_agent", req.headers.get('User-Agent') || '');
        this.addNumberToCtx(exec_ctx, 'http.request.version', parseInt(req.headers.get('x-http.request.version') || "1", 10));
        this.addStringToCtx(exec_ctx, 'http.x_forwarded_for', req.headers.get('X-Forwarded-For') || '');
        this.addIpAddrToCtx(exec_ctx, 'ip.src', req.headers.get('x-ip.src') || '0.0.0.0');
        this.addNumberToCtx(exec_ctx, 'ip.geoip.asnum', parseInt(req.headers.get('x-ip.geoip.asnum') || '0', 10));
        this.addStringToCtx(exec_ctx, 'ip.geoip.continent', req.headers.get('x-ip.geoip.continent') || '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.country', req.headers.get('x-ip.geoip.country') || '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.subdivision_1_iso_code', req.headers.get('x-ip.geoip.subdivision_1_iso_code') || '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.subdivision_2_iso_code', req.headers.get('x-ip.geoip.subdivision_2_iso_code') || '');
        this.addBoolenToCtx(exec_ctx, 'ip.geoip.is_in_european_union', (req.headers.get('x-ip.geoip.is_in_european_union') || '').toLowerCase() === "true");
        this.addBoolenToCtx(exec_ctx, 'ssl', url.protocol === 'https:');
        try {
            let matchResult = wirefilter.wirefilter_match(this.filter, exec_ctx);
            if (matchResult.ok.success != 1) {
                throw Error(`Filter can't be matched: ${matchResult.err.msg.data}`)
            }
            return matchResult.ok.value;
        } finally {
            wirefilter.wirefilter_free_execution_context(exec_ctx);
        }
    }

    private addNumberToCtx(execCtx: any, name: string, value: number) {
        FirewallRule.checkAdded(this.wirefilter.wirefilter_add_int_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            value
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addStringToCtx(execCtx: any, name: string, value: string) {
        FirewallRule.checkAdded(this.wirefilter.wirefilter_add_bytes_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            wirefilterByteArray(value)
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addBoolenToCtx(execCtx: any, name: string, value: boolean) {
        FirewallRule.checkAdded(this.wirefilter.wirefilter_add_bool_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            value
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addIpAddrToCtx(execCtx: any, name: string, value: string) {
        if (value.indexOf('.') != -1) {
            const ipv4 = new Address4(value).toArray();
            FirewallRule.checkAdded(this.wirefilter.wirefilter_add_ipv4_value_to_execution_context(
                execCtx,
                wirefilterString(name),
                ipv4,
            ), `Failed to add ${name}=${value} to the context`);
        } else if (value.indexOf(':') != -1) {
            const ipv6 = new Address6(value).toUnsignedByteArray();
            FirewallRule.checkAdded(this.wirefilter.wirefilter_add_ipv6_value_to_execution_context(
                execCtx,
                wirefilterString(name),
                ipv6,
            ), `Failed to add ${name}=${value} to the context`);
        } else {
            throw new Error(`Can't parse IP address: ${value}`)
        }
    }

    private static checkAdded(added: boolean, msg: string) {
        if (!added) {
            throw new Error(msg);
        }
    }
}
