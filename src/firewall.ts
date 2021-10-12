/* eslint @typescript-eslint/no-explicit-any: 0 */
import {
    initWirefilter,
    wirefilter_externally_allocated_byte_arr_t,
    wirefilter_externally_allocated_str_t,
    WIREFILTER_TYPE_BOOL,
    WIREFILTER_TYPE_BYTES,
    WIREFILTER_TYPE_INT,
    WIREFILTER_TYPE_IP
} from './wirefilter';
import {Headers, Request as FetchRequest, RequestInfo, RequestInit} from 'node-fetch';
import {Address4, Address6} from 'ip-address';
import * as path from 'path';

function wirefilterString(s: string) {
    const str = new wirefilter_externally_allocated_str_t();
    str.data = s;
    str.length = s.length;
    return str;
}

function wirefilterByteArray(s: string) {
    const str = new wirefilter_externally_allocated_byte_arr_t();
    str.data = Buffer.alloc(s.length, s);
    str.length = s.length;
    return str;
}

function checkAdded(added: boolean, msg: string) {
    if (!added) {
        throw new Error(msg);
    }
}

function addString(wirefilter: any, scheme: any, name: string): void {
    checkAdded(wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        WIREFILTER_TYPE_BYTES
    ), `Failed to add ${name} to the scheme`);
}

// Map<String, Array<String>>
function addMapToStrArray(wirefilter: any, scheme: any, name: string) {
    checkAdded(wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        wirefilter.wirefilter_create_map_type(
            wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES)
        )
    ), `Failed to add ${name} to the scheme`);
}

// Array<String>
function addStrArray(wirefilter: any, scheme: any, name: string) {
    checkAdded(wirefilter.wirefilter_add_type_field_to_scheme(
        scheme,
        wirefilterString(name),
        wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES)
    ), `Failed to add ${name} to the scheme`);
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

function parsePort(req: Request): number {
    if (req.port) {
        return req.port;
    }
    const url = new URL(req.url);
    if (url.port) {
        return parseInt(url.port, 10);
    }
    if (url.protocol == 'https:') {
        return 443;
    }
    return 80;
}


// the map isn't URL-decoded, so can't use searchParams since re-encoding can change
// the values.
function paramsToMap(params: string): Map<string, string[]> {
    if (params.length == 0) {
        return new Map<string, string[]>();
    }
    const map = new Map<string, string[]>();
    if (params[0] == '?') {
        params = params.substring(1);
    }
    params.split('&')
        .map(v => v.split('='))
        .forEach(pair => {
            const [key, val] = pair;
            const arr = map.get(key);
            if (arr) {
                arr.push(val);
            } else {
                map.set(key, [val]);
            }
        });
    return map;
}

function paramNamesToArray(params: string): string[] {
    if (params.length == 0) {
        return [];
    }
    return params.substring(1).split('&')
        .map(v => v.split('=')[0]);
}

function paramValuesToArray(params: string): string[] {
    if (params.length == 0) {
        return [];
    }
    return params.substring(1).split('&')
        .map(v => v.split('=')[1]);
}

function headersToMap(headers: Headers): Map<string, string[]> {
    const map = new Map<string, string[]>();
    headers.forEach((val, key) => {
        const arr = map.get(key);
        if (arr) {
            arr.push(val);
        } else {
            map.set(key, [val]);
        }
    });
    return map;
}

/**
 * Firewall that defines the schema for the rules supported by the Cloudflare WAF language.
 *
 * see https://developers.cloudflare.com/firewall/cf-firewall-language/
 */
export class Firewall {
    private readonly wirefilter: any;
    private readonly scheme: any;

    constructor() {
        let libPath: string;
        switch (process.platform) {
            case 'darwin':
                libPath = path.join(__dirname, '..', 'lib', 'libwirefilter_ffi.dylib');
                break;
            case 'linux':
                libPath = path.join(__dirname, '..', 'lib', 'libwirefilter_ffi.so');
                break;
            default:
                throw new Error(`Unsupported platform: ${process.platform}`);
        }
        const wirefilter = initWirefilter(libPath);
        const scheme = wirefilter.wirefilter_create_scheme();
        // add transformation functions
        wirefilter.add_standard_functions(scheme);
        // Standard fields
        addString(wirefilter, scheme, 'http.cookie');
        addString(wirefilter, scheme, 'http.host');
        addString(wirefilter, scheme, 'http.referer');
        addString(wirefilter, scheme, 'http.request.full_uri');
        addString(wirefilter, scheme, 'http.request.method');
        addString(wirefilter, scheme, 'http.request.uri');
        addString(wirefilter, scheme, 'http.request.uri.path');
        addString(wirefilter, scheme, 'http.request.uri.query');
        addString(wirefilter, scheme, 'http.user_agent');
        addNumber(wirefilter, scheme, 'http.request.version');
        addString(wirefilter, scheme, 'http.x_forwarded_for');
        addIPaddr(wirefilter, scheme, 'ip.src');
        addNumber(wirefilter, scheme, 'ip.geoip.asnum');
        addString(wirefilter, scheme, 'ip.geoip.continent');
        addString(wirefilter, scheme, 'ip.geoip.country');
        addString(wirefilter, scheme, 'ip.geoip.subdivision_1_iso_code');
        addString(wirefilter, scheme, 'ip.geoip.subdivision_2_iso_code');
        addBoolen(wirefilter, scheme, 'ip.geoip.is_in_european_union');
        addBoolen(wirefilter, scheme, 'ssl');
        // Argument and value fields for URIs
        addMapToStrArray(wirefilter, scheme, 'http.request.uri.args');
        addStrArray(wirefilter, scheme, 'http.request.uri.args.names');
        addStrArray(wirefilter, scheme, 'http.request.uri.args.values');
        // Header fields
        addMapToStrArray(wirefilter, scheme, 'http.request.headers');
        addStrArray(wirefilter, scheme, 'http.request.headers.names');
        addStrArray(wirefilter, scheme, 'http.request.headers.values');
        addBoolen(wirefilter, scheme, 'http.request.headers.truncated');
        // Body fields
        addString(wirefilter, scheme, 'http.request.body.raw');
        addBoolen(wirefilter, scheme, 'http.request.body.truncated');
        addMapToStrArray(wirefilter, scheme, 'http.request.body.form');
        addStrArray(wirefilter, scheme, 'http.request.body.form.names');
        addStrArray(wirefilter, scheme, 'http.request.body.form.values');
        // Dynamic fields
        addBoolen(wirefilter, scheme, 'cf.bot_management.verified_bot');
        addNumber(wirefilter, scheme, 'cf.bot_management.score');
        addNumber(wirefilter, scheme, 'cf.threat_score');
        addNumber(wirefilter, scheme, 'cf.edge.server_port');
        addBoolen(wirefilter, scheme, 'cf.client.bot');
        addNumber(wirefilter, scheme, 'cf.client_trust_score');
        this.wirefilter = wirefilter;
        this.scheme = scheme;
    }

    /**
     * Creates a firewall rule from a WAF language expression.
     *
     * @param rule waf language expression
     */
    createRule(rule: string): FirewallRule {
        return new WirefilterFirewallRule(this.wirefilter, this.scheme, rule);
    }
}

/**
 * The set of extension fields that can't be directly derived from the supplied request, and need to be specified
 * explicitly.
 */
export type CfRequestExt = Readonly<{
    'http.request.version'?: number;
    'ip.src'?: string;
    'ip.geoip.asnum'?: number;
    'ip.geoip.continent'?: string;
    'ip.geoip.country'?: string;
    'ip.geoip.subdivision_1_iso_code'?: string;
    'ip.geoip.subdivision_2_iso_code'?: string;
    'ip.geoip.is_in_european_union'?: boolean;
    'http.request.headers.truncated'?: boolean;
    'http.request.body.truncated'?: boolean;
    'cf.bot_management.verified_bot'?: boolean;
    'cf.bot_management.score'?: number;
    'cf.client_trust_score'?: number;
    'cf.threat_score'?: number;
    'cf.client.bot'?: boolean;
}>;

/**
 * Cloudflare fields request extension.
 */
export interface CfRequestInit extends RequestInit {
    cf?: CfRequestExt
}

/**
 * A request potentially augmented with the Cloudflare extension fields.
 */
export class Request extends FetchRequest {
    readonly cf: CfRequestExt;

    constructor(input: RequestInfo, init?: CfRequestInit) {
        super(input, init);
        this.cf = (init || {}).cf || {};
    }
}

/**
 * Firewall rule that can be matched against the request.
 */
export interface FirewallRule {
    /**
     * Matches the request against the request.
     *
     * Note, not all of the parameters can be obtained from a request. For instance, thread score, geoip, etc.
     * can't be easily obtained from the request. For such cases, a special cf object can be supplied, e.g. for
     * 'ip.src, cf: {"ip.scr": '1.2.3.4'} can be used.
     *
     * @param req the request which the rule will matched against.
     */
    match(req: Request): boolean;
}

class WirefilterFirewallRule implements FirewallRule {
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
            throw Error(`Can't parse the rule: ${parsingResult.err.msg.data}`);
        }
        const ast = parsingResult.ok.ast;
        const compilingResult = wirefilter.wirefilter_compile_filter(ast);
        if (compilingResult.ok.success != 1) {
            throw Error(`Can't compile the rule: ${compilingResult.err.msg.data}`);
        }
        this.filter = compilingResult.ok.filter;
    }

    match(req: Request): boolean {
        const wirefilter = this.wirefilter;
        const exec_ctx = wirefilter.wirefilter_create_execution_context(this.scheme);
        const url = new URL(req.url);
        // Standard fields
        this.addStringToCtx(exec_ctx, 'http.cookie', req.headers.get('Cookie') ?? '');
        this.addStringToCtx(exec_ctx, 'http.host', url.hostname);
        this.addStringToCtx(exec_ctx, 'http.referer', req.headers.get('Referer') ?? '');
        this.addStringToCtx(exec_ctx, 'http.request.full_uri', req.url);
        this.addStringToCtx(exec_ctx, 'http.request.method', req.method);
        this.addStringToCtx(exec_ctx, 'http.request.uri', `${url.pathname}${url.search}`);
        this.addStringToCtx(exec_ctx, 'http.request.uri.path', url.pathname);
        this.addStringToCtx(exec_ctx, 'http.request.uri.query', url.searchParams.toString());
        this.addStringToCtx(exec_ctx, 'http.user_agent', req.headers.get('User-Agent') ?? '');
        this.addNumberToCtx(exec_ctx, 'http.request.version', req.cf['http.request.version'] ?? 1);
        this.addStringToCtx(exec_ctx, 'http.x_forwarded_for', req.headers.get('X-Forwarded-For') ?? '');
        this.addIpAddrToCtx(exec_ctx, 'ip.src', req.cf['ip.src'] ?? '0.0.0.0');
        this.addNumberToCtx(exec_ctx, 'ip.geoip.asnum', req.cf['ip.geoip.asnum'] ?? 0);
        this.addStringToCtx(exec_ctx, 'ip.geoip.continent', req.cf['ip.geoip.continent'] ?? '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.country', req.cf['ip.geoip.country'] ?? '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.subdivision_1_iso_code', req.cf['ip.geoip.subdivision_1_iso_code'] ?? '');
        this.addStringToCtx(exec_ctx, 'ip.geoip.subdivision_2_iso_code', req.cf['ip.geoip.subdivision_2_iso_code'] ?? '');
        this.addBoolenToCtx(exec_ctx, 'ip.geoip.is_in_european_union', req.cf['ip.geoip.is_in_european_union'] ?? false);
        this.addBoolenToCtx(exec_ctx, 'ssl', url.protocol === 'https:');
        // Argument and value fields for URIs
        this.addMapStrToCtx(exec_ctx, 'http.request.uri.args', paramsToMap(url.search));
        this.addStrArrayCtx(exec_ctx, 'http.request.uri.args.names', paramNamesToArray(url.search));
        this.addStrArrayCtx(exec_ctx, 'http.request.uri.args.values', paramValuesToArray(url.search));
        // Header fields
        this.addMapStrToCtx(exec_ctx, 'http.request.headers', headersToMap(req.headers));
        this.addStrArrayCtx(exec_ctx, 'http.request.headers.names', [...req.headers.keys()]);
        this.addStrArrayCtx(exec_ctx, 'http.request.headers.values', ([] as string[]).concat(...req.headers.values()));
        this.addBoolenToCtx(exec_ctx, 'http.request.headers.truncated', req.cf['http.request.headers.truncated'] ?? false);
        // Body fields
        this.addStringToCtx(exec_ctx, 'http.request.body.raw', String(req.body ?? ''));
        this.addBoolenToCtx(exec_ctx, 'http.request.body.truncated', req.cf['http.request.body.truncated'] ?? false);
        let bodyParams: Map<string, string[]>;
        if ((req.headers.get('Content-Type') ?? '').startsWith('application/x-www-form-urlencoded')) {
            bodyParams = paramsToMap(String(req.body ?? ''));
        } else {
            bodyParams = new Map<string, string[]>();
        }
        this.addMapStrToCtx(exec_ctx, 'http.request.body.form', bodyParams);
        this.addStrArrayCtx(exec_ctx, 'http.request.body.form.names', [...bodyParams.keys()]);
        this.addStrArrayCtx(exec_ctx, 'http.request.body.form.values', ([] as string[]).concat(...bodyParams.values()));
        // Dynamic fields
        this.addBoolenToCtx(exec_ctx, 'cf.bot_management.verified_bot', req.cf['cf.bot_management.verified_bot'] ?? false);
        this.addNumberToCtx(exec_ctx, 'cf.bot_management.score', req.cf['cf.bot_management.score'] ?? 100);
        this.addNumberToCtx(exec_ctx, 'cf.client_trust_score', req.cf['cf.client_trust_score'] ?? 100);
        this.addNumberToCtx(exec_ctx, 'cf.threat_score', req.cf['cf.threat_score'] ?? 100);
        this.addNumberToCtx(exec_ctx, 'cf.edge.server_port', parsePort(req));
        this.addBoolenToCtx(exec_ctx, 'cf.client.bot', req.cf['cf.client.bot'] ?? false);
        try {
            const matchResult = wirefilter.wirefilter_match(this.filter, exec_ctx);
            if (matchResult.ok.success != 1) {
                throw Error(`Filter can't be matched: ${matchResult.err.msg.data}`);
            }
            return matchResult.ok.value;
        } finally {
            wirefilter.wirefilter_free_execution_context(exec_ctx);
        }
    }

    private addNumberToCtx(execCtx: any, name: string, value: number) {
        checkAdded(this.wirefilter.wirefilter_add_int_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            value
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addStringToCtx(execCtx: any, name: string, value: string) {
        checkAdded(this.wirefilter.wirefilter_add_bytes_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            wirefilterByteArray(value)
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addBoolenToCtx(execCtx: any, name: string, value: boolean) {
        checkAdded(this.wirefilter.wirefilter_add_bool_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            value
        ), `Failed to add ${name}=${value} to the context`);
    }

    private addIpAddrToCtx(execCtx: any, name: string, value: string) {
        if (value.indexOf('.') != -1) {
            const ipv4 = new Address4(value).toArray();
            checkAdded(this.wirefilter.wirefilter_add_ipv4_value_to_execution_context(
                execCtx,
                wirefilterString(name),
                ipv4,
            ), `Failed to add ${name}=${value} to the context`);
        } else if (value.indexOf(':') != -1) {
            const ipv6 = new Address6(value).toUnsignedByteArray();
            checkAdded(this.wirefilter.wirefilter_add_ipv6_value_to_execution_context(
                execCtx,
                wirefilterString(name),
                ipv6,
            ), `Failed to add ${name}=${value} to the context`);
        } else {
            throw new Error(`Can't parse IP address: ${value}`);
        }
    }

    private addMapStrToCtx(execCtx: any, name: string, value: Map<string, string[]>) {
        const arrayType = this.wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES);
        const mapValue = this.wirefilter.wirefilter_create_map(arrayType);
        value.forEach((mapVal, mapKey) => {
            const arr = this.wirefilter.wirefilter_create_array(WIREFILTER_TYPE_BYTES);
            mapVal.forEach((val, ind) => {
                checkAdded(this.wirefilter.wirefilter_add_bytes_value_to_array(
                    arr,
                    ind,
                    wirefilterByteArray(val)
                ), `Failed to add a ${val} to array`);
            });
            checkAdded(this.wirefilter.wirefilter_add_array_value_to_map(
                mapValue,
                wirefilterString(mapKey),
                arr
            ), `Failed to add ${mapKey} value to map`);
        });
        checkAdded(this.wirefilter.wirefilter_add_map_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            mapValue,
        ), `Failed to add ${name}=${JSON.stringify(value)} to the context`);
    }

    private addStrArrayCtx(execCtx: any, name: string, value: string[]) {
        const arr = this.wirefilter.wirefilter_create_array(WIREFILTER_TYPE_BYTES);
        value.forEach((val, ind) => {
            checkAdded(this.wirefilter.wirefilter_add_bytes_value_to_array(
                arr,
                ind,
                wirefilterByteArray(val)
            ), `Failed to add a ${val} to array`);
        });
        checkAdded(this.wirefilter.wirefilter_add_array_value_to_execution_context(
            execCtx,
            wirefilterString(name),
            arr,
        ), `Failed to add ${name}=${JSON.stringify(value)} to the context`);
    }
}
