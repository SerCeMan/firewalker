/* eslint @typescript-eslint/no-explicit-any: 0 */
import {
  initWirefilter,
  wirefilter_externally_allocated_byte_arr_t,
  wirefilter_externally_allocated_str_t,
  WIREFILTER_TYPE_BOOL,
  WIREFILTER_TYPE_BYTES,
  WIREFILTER_TYPE_INT,
  WIREFILTER_TYPE_IP,
} from './wirefilter';
import { Headers, Request as FetchRequest, RequestInfo, RequestInit } from 'node-fetch';
import { Address4, Address6 } from 'ip-address';
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
  checkAdded(
    wirefilter.wirefilter_add_type_field_to_scheme(
      scheme,
      wirefilterString(name),
      WIREFILTER_TYPE_BYTES,
    ),
    `Failed to add ${name} to the scheme`,
  );
}

// Map<String, Array<String>>
function addMapToStrArray(wirefilter: any, scheme: any, name: string) {
  checkAdded(
    wirefilter.wirefilter_add_type_field_to_scheme(
      scheme,
      wirefilterString(name),
      wirefilter.wirefilter_create_map_type(
        wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES),
      ),
    ),
    `Failed to add ${name} to the scheme`,
  );
}

// Array<String>
function addStrArray(wirefilter: any, scheme: any, name: string) {
  checkAdded(
    wirefilter.wirefilter_add_type_field_to_scheme(
      scheme,
      wirefilterString(name),
      wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES),
    ),
    `Failed to add ${name} to the scheme`,
  );
}

// Array<Number>
function addNumArray(wirefilter: any, scheme: any, name: string) {
  checkAdded(
    wirefilter.wirefilter_add_type_field_to_scheme(
      scheme,
      wirefilterString(name),
      wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_INT),
    ),
    `Failed to add ${name} to the scheme`,
  );
}

function addIPaddr(wirefilter: any, scheme: any, name: string): void {
  wirefilter.wirefilter_add_type_field_to_scheme(
    scheme,
    wirefilterString(name),
    WIREFILTER_TYPE_IP,
  );
}

function addNumber(wirefilter: any, scheme: any, name: string): void {
  wirefilter.wirefilter_add_type_field_to_scheme(
    scheme,
    wirefilterString(name),
    WIREFILTER_TYPE_INT,
  );
}

function addBoolen(wirefilter: any, scheme: any, name: string): void {
  wirefilter.wirefilter_add_type_field_to_scheme(
    scheme,
    wirefilterString(name),
    WIREFILTER_TYPE_BOOL,
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
  params
    .split('&')
    .map((v) => v.split('='))
    .forEach((pair) => {
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

function parseExtension(path: string): string {
  const lastSegment = path.split('/').pop() ?? '';
  const index = lastSegment.lastIndexOf('.');
  if (index === -1 || index === 0 || index === lastSegment.length - 1) {
    // no extension
    // Single dot is the first char
    // No trailing characters
    return '';
  }
  return lastSegment.substr(index + 1).toLowerCase();
}

function paramNamesToArray(params: string): string[] {
  if (params.length == 0) {
    return [];
  }
  return params
    .substring(1)
    .split('&')
    .map((v) => v.split('=')[0]);
}

function paramValuesToArray(params: string): string[] {
  if (params.length == 0) {
    return [];
  }
  return params
    .substring(1)
    .split('&')
    .map((v) => v.split('=')[1]);
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

function cookiesToMap(cookieString: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  cookieString
    .split(';')
    .map((v) => v.split('='))
    .forEach((val) => {
      // Skip invalid cookies
      if (val.length === 2) {
        // Only key is URL decoded
        const key = decodeURIComponent(val[0].trim());
        const arr = map.get(key);
        if (arr) {
          arr.push(val[1].trim());
        } else {
          map.set(key, [val[1].trim()]);
        }
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
    let libName: string;
    switch (process.platform) {
      case 'darwin':
        libName = 'libwirefilter_ffi';
        if (process.arch == 'arm64') {
          libName += '_aarch64';
        }
        libPath = path.join(__dirname, '..', 'lib', `${libName}.dylib`);
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
    addMapToStrArray(wirefilter, scheme, 'http.request.cookies');
    addString(wirefilter, scheme, 'http.request.uri');
    addString(wirefilter, scheme, 'http.request.uri.path');
    addString(wirefilter, scheme, 'http.request.uri.path.extension');
    addString(wirefilter, scheme, 'http.request.uri.query');
    addString(wirefilter, scheme, 'http.user_agent');
    addNumber(wirefilter, scheme, 'http.request.version');
    addString(wirefilter, scheme, 'http.x_forwarded_for');
    addIPaddr(wirefilter, scheme, 'ip.src');
    addString(wirefilter, scheme, 'ip.src.lat');
    addString(wirefilter, scheme, 'ip.src.lon');
    addString(wirefilter, scheme, 'ip.src.city');
    addString(wirefilter, scheme, 'ip.src.postal_code');
    addString(wirefilter, scheme, 'ip.src.metro_code');
    addString(wirefilter, scheme, 'ip.src.region');
    addString(wirefilter, scheme, 'ip.src.region_code');
    addNumber(wirefilter, scheme, 'ip.src.asnum');
    addString(wirefilter, scheme, 'ip.src.continent');
    addString(wirefilter, scheme, 'ip.src.country');
    addString(wirefilter, scheme, 'ip.src.subdivision_1_iso_code');
    addString(wirefilter, scheme, 'ip.src.subdivision_2_iso_code');
    addBoolen(wirefilter, scheme, 'ip.src.is_in_european_union');
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
    addNumber(wirefilter, scheme, 'http.request.body.size');
    addMapToStrArray(wirefilter, scheme, 'http.request.body.form');
    addStrArray(wirefilter, scheme, 'http.request.body.form.names');
    addStrArray(wirefilter, scheme, 'http.request.body.form.values');
    addString(wirefilter, scheme, 'http.request.body.mime');
    // Dynamic fields
    addString(wirefilter, scheme, 'cf.bot_management.ja3_hash');
    addBoolen(wirefilter, scheme, 'cf.bot_management.js_detection.passed');
    addNumArray(wirefilter, scheme, 'cf.bot_management.detection_ids');
    addNumber(wirefilter, scheme, 'cf.bot_management.score');
    addBoolen(wirefilter, scheme, 'cf.bot_management.static_resource');
    addBoolen(wirefilter, scheme, 'cf.bot_management.verified_bot');
    addBoolen(wirefilter, scheme, 'cf.bot_management.corporate_proxy');
    addString(wirefilter, scheme, 'cf.ray_id');
    addNumber(wirefilter, scheme, 'cf.threat_score');
    addNumber(wirefilter, scheme, 'cf.edge.server_port');
    addBoolen(wirefilter, scheme, 'cf.client.bot');
    addNumber(wirefilter, scheme, 'cf.client_trust_score');
    addString(wirefilter, scheme, 'cf.verified_bot_category');
    addNumber(wirefilter, scheme, 'cf.waf.score');
    addNumber(wirefilter, scheme, 'cf.waf.score.sqli');
    addNumber(wirefilter, scheme, 'cf.waf.score.xss');
    addNumber(wirefilter, scheme, 'cf.waf.score.rce');
    addString(wirefilter, scheme, 'cf.waf.score.class');
    addString(wirefilter, scheme, 'cf.worker.upstream_zone');
    this.wirefilter = wirefilter;
    this.scheme = scheme;
  }

  /**
   * Creates a firewall rule from a WAF language expression.
   *
   * @param rule waf language expression
   */
  createRule(rule: string, lists: Lists = {}): FirewallRule {
    return new WirefilterFirewallRule(this.wirefilter, this.scheme, rule, lists);
  }

  /**
   * Creates a new empty firewall ruleset
   * @returns ruleset
   */
  createRuleSet(): FirewallRuleset {
    return new FirewallRuleset(this.wirefilter, this.scheme);
  }
}

// Allows either of the supported fields to be provided but prefer ip.src namespace
function extractIpInfo(cf: CfRequestExt): IpInfo {
  return {
    'ip.src': cf['ip.src'],
    'ip.src.lat': cf['ip.src.lat'],
    'ip.src.lon': cf['ip.src.lon'],
    'ip.src.city': cf['ip.src.city'],
    'ip.src.postal_code': cf['ip.src.postal_code'],
    'ip.src.metro_code': cf['ip.src.metro_code'],
    'ip.src.region': cf['ip.src.region'],
    'ip.src.region_code': cf['ip.src.region_code'],
    'ip.src.timezone.name': cf['ip.src.timezone.name'],
    'ip.src.asnum': cf['ip.src.asnum'] ?? cf['ip.geoip.asnum'],
    'ip.src.continent': cf['ip.src.continent'] ?? cf['ip.geoip.continent'],
    'ip.src.country': cf['ip.src.country'] ?? cf['ip.geoip.country'],
    'ip.src.subdivision_1_iso_code':
      cf['ip.src.subdivision_1_iso_code'] ?? cf['ip.geoip.subdivision_1_iso_code'],
    'ip.src.subdivision_2_iso_code':
      cf['ip.src.subdivision_2_iso_code'] ?? cf['ip.geoip.subdivision_2_iso_code'],
    'ip.src.is_in_european_union':
      cf['ip.src.is_in_european_union'] ?? cf['ip.geoip.is_in_european_union'],
  };
}

type IpInfo = Readonly<{
  'ip.src'?: string,
  'ip.src.lat'?: string,
  'ip.src.lon'?: string,
  'ip.src.city'?: string,
  'ip.src.postal_code'?: string,
  'ip.src.metro_code'?: string,
  'ip.src.region'?: string,
  'ip.src.region_code'?: string,
  'ip.src.timezone.name'?: string,
  'ip.src.asnum'?: number,
  'ip.src.continent'?: string,
  'ip.src.country'?: string,
  'ip.src.subdivision_1_iso_code'?: string,
  'ip.src.subdivision_2_iso_code'?: string,
  'ip.src.is_in_european_union'?: boolean,
}>;

/**
 * The set of extension fields that can't be directly derived from the supplied request, and need to be specified
 * explicitly.
 */
export type CfRequestExt = Readonly<{
  'http.request.version'?: number,
  'ip.src'?: string,
  'ip.src.lat'?: string,
  'ip.src.lon'?: string,
  'ip.src.city'?: string,
  'ip.src.postal_code'?: string,
  'ip.src.metro_code'?: string,
  'ip.src.region'?: string,
  'ip.src.region_code'?: string,
  'ip.src.timezone.name'?: string,
  'ip.src.asnum'?: number,
  'ip.src.continent'?: string,
  'ip.src.country'?: string,
  'ip.src.subdivision_1_iso_code'?: string,
  'ip.src.subdivision_2_iso_code'?: string,
  'ip.src.is_in_european_union'?: boolean,
  'ip.geoip.asnum'?: number,
  'ip.geoip.continent'?: string,
  'ip.geoip.country'?: string,
  'ip.geoip.subdivision_1_iso_code'?: string,
  'ip.geoip.subdivision_2_iso_code'?: string,
  'ip.geoip.is_in_european_union'?: boolean,
  'http.request.headers.truncated'?: boolean,
  'http.request.body.truncated'?: boolean,
  'cf.bot_management.score'?: number,
  'cf.bot_management.ja3_hash'?: string,
  'cf.bot_management.js_detection.passed'?: boolean,
  'cf.bot_management.detection_ids'?: number[],
  'cf.bot_management.static_resource'?: boolean,
  'cf.bot_management.verified_bot'?: boolean,
  'cf.bot_management.corporate_proxy'?: boolean,
  'cf.client_trust_score'?: number,
  'cf.ray_id'?: string,
  'cf.threat_score'?: number,
  'cf.client.bot'?: boolean,
  'cf.verified_bot_category'?: string,
  'cf.waf.score'?: number,
  'cf.waf.score.sqli'?: number,
  'cf.waf.score.xss'?: number,
  'cf.waf.score.rce'?: number,
  'cf.waf.score.class'?: string,
  'cf.worker.upstream_zone'?: string,
}>;

/**
 * Cloudflare fields request extension.
 */
export interface CfRequestInit extends RequestInit {
  cf?: CfRequestExt;
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
   * 'ip.src, cf: {"ip.src": '1.2.3.4'} can be used.
   *
   * @param req the request which the rule will matched against.
   */
  match(req: Request): boolean;
}

type Lists = {
  int?: Record<string, number[]>,
  ip?: Record<string, string[]>,
};

class WirefilterFirewallRule implements FirewallRule {
  private readonly filter: any;

  constructor(
    private readonly wirefilter: any, //
    private readonly scheme: any, //
    private readonly rule: string, //
    private readonly lists: Lists = {}, //
  ) {
    const parsingResult = wirefilter.wirefilter_parse_filter(scheme, wirefilterString(rule));
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
    const exec_ctx = ExecutionContext.buildFromRequest(
      this.wirefilter,
      this.scheme,
      this.lists,
      req,
    );

    try {
      return this.matchUsingContext(exec_ctx);
    } finally {
      exec_ctx.free();
    }
  }

  matchUsingContext(execCtx: ExecutionContext): boolean {
    const matchResult = this.wirefilter.wirefilter_match(this.filter, execCtx.internalPointer);
    if (matchResult.ok.success != 1) {
      throw Error(`Filter can't be matched: ${matchResult.err.msg.data}`);
    }
    return matchResult.ok.value;
  }
}

type Phase = 'http_ratelimit' | 'http_request_sbfm' | 'http_request_firewall_managed';
type Product = 'zoneLockdown' | 'uaBlock' | 'bic' | 'hot' | 'securityLevel' | 'rateLimit' | 'waf';

export type FirewallAction =
  | {
      type: 'skip',
      ruleset?: 'current',
      phases?: Phase[],
      products?: Product[],
    }
  | {
      type: 'log',
    }
  | TerminalAction;

type TerminalAction = { type: 'block' | 'challenge' | 'managed_challenge' | 'js_challenge' };

const TERMINAL_ACTIONS: Readonly<TerminalAction['type'][]> = Object.freeze([
  'block',
  'challenge',
  'managed_challenge',
  'js_challenge',
]);

const isTerminalAction = (action: FirewallAction): action is TerminalAction => {
  return (TERMINAL_ACTIONS as string[]).includes(action.type);
};

const isSkipCurrent = (action: FirewallAction): boolean => {
  return action.type === 'skip' && action.ruleset === 'current';
};

type Rule = {
  id: string,
  expression: WirefilterFirewallRule,
  action: FirewallAction,
};

export class FirewallRuleset {
  private defaultLists: Lists = {};
  private rules: Rule[] = [];

  constructor(
    private wirefilter: any,
    private scheme: any,
  ) {}

  /**
   * Sets the lists to be added to the execution context for rule evaluation
   * @param lists - lists to be added
   * @returns this for method chaining
   */
  setDefaultLists(lists: Lists): this {
    this.defaultLists = lists;
    return this;
  }

  /**
   * Appends a new rule into the firewall at the end of the chain
   *
   * @param rule Object with an id and a WAF language expression
   */
  addRule(rule: { id: string, expression: string, action: FirewallAction }): this {
    this.rules.push({
      id: rule.id,
      expression: new WirefilterFirewallRule(this.wirefilter, this.scheme, rule.expression),
      action: rule.action,
    });
    return this;
  }

  /**
   * Iterates through the list of rules and returns the matching rule id
   *
   * @param request incoming request to be matched against
   * @returns the provided rule id if a successful match is made, undefined otherwise
   */
  matchRequest(request: Request): RequestMatchResults {
    const results = new RulesetMatchResults();
    const execCtx = ExecutionContext.buildFromRequest(
      this.wirefilter,
      this.scheme,
      this.defaultLists,
      request,
    );
    try {
      for (const rule of this.rules) {
        if (!rule.expression.matchUsingContext(execCtx)) {
          continue;
        }

        results.matches.push({
          ruleId: rule.id,
          action: { ...rule.action },
        });

        if (isTerminalAction(rule.action)) {
          break;
        }
        if (isSkipCurrent(rule.action)) {
          break;
        }
      }
    } finally {
      execCtx.free();
    }
    return results;
  }
}

export interface RuleMatch {
  ruleId: string;
  action: FirewallAction;
}

export interface RequestMatchResults {
  matches: RuleMatch[];
  skippedPhases: Phase[];
  skippedProducts: Product[];
  loggedRules: string[];
  terminatedEarly: boolean;
  terminalAction: { action: { type: 'no_match' } } | RuleMatch;
}

class RulesetMatchResults implements RequestMatchResults {
  matches: RuleMatch[] = [];

  get skippedPhases(): Phase[] {
    const phases = new Set<Phase>();
    for (const m of this.matches) {
      if (m.action.type === 'skip') {
        m.action.phases?.forEach((p) => phases.add(p));
      }
    }
    return Array.from(phases);
  }

  get skippedProducts(): Product[] {
    const products = new Set<Product>();
    for (const m of this.matches) {
      if (m.action.type === 'skip') {
        m.action.products?.forEach((p) => products.add(p));
      }
    }
    return Array.from(products);
  }

  get loggedRules(): string[] {
    return this.matches.filter((m) => m.action.type === 'log').map((m) => m.ruleId);
  }

  get terminatedEarly(): boolean {
    return this.terminalAction.action.type !== 'no_match';
  }

  get terminalAction(): RuleMatch | { action: { type: 'no_match' } } {
    const terminalMatches = this.matches.filter(
      (m) => isTerminalAction(m.action) || isSkipCurrent(m.action),
    );

    if (terminalMatches.length === 0) {
      return { action: { type: 'no_match' } };
    }

    return terminalMatches[terminalMatches.length - 1];
  }
}

type IPParseResult = { type: 'v4', ip: number[] } | { type: 'v6', ip: number[] };

const parseIp = (value: string): IPParseResult => {
  if (value.indexOf('.') != -1) {
    const ipv4 = new Address4(value).toArray();
    return { type: 'v4', ip: ipv4 };
  } else if (value.indexOf(':') != -1) {
    const ipv6 = new Address6(value).toUnsignedByteArray();
    return { type: 'v6', ip: ipv6 };
  } else {
    throw new Error(`Unable to parse ip address '${value}'`);
  }
};

class ExecutionContext {
  private execCtx: any;

  static buildFromRequest(
    wirefilter: any,
    scheme: any,
    lists: Lists,
    req: Request,
  ): ExecutionContext {
    const exec_ctx = new ExecutionContext(wirefilter, scheme);
    const url = new URL(req.url);
    // Standard fields
    exec_ctx.addString('http.cookie', req.headers.get('Cookie') ?? '');
    exec_ctx.addString('http.host', url.hostname);
    exec_ctx.addString('http.referer', req.headers.get('Referer') ?? '');
    exec_ctx.addString('http.request.full_uri', req.url);
    exec_ctx.addString('http.request.method', req.method);
    exec_ctx.addStringMap('http.request.cookies', cookiesToMap(req.headers.get('Cookie') ?? ''));
    exec_ctx.addString('http.request.uri', `${url.pathname}${url.search}`);
    exec_ctx.addString('http.request.uri.path', url.pathname);
    exec_ctx.addString('http.request.uri.path.extension', parseExtension(url.pathname));
    exec_ctx.addString('http.request.uri.query', url.searchParams.toString());
    exec_ctx.addString('http.user_agent', req.headers.get('User-Agent') ?? '');
    exec_ctx.addNumber('http.request.version', req.cf['http.request.version'] ?? 1);
    exec_ctx.addString('http.x_forwarded_for', req.headers.get('X-Forwarded-For') ?? '');
    // handle duplicated fields for ip info
    const ipInfo = extractIpInfo(req.cf);
    exec_ctx.addIpAddr('ip.src', ipInfo['ip.src'] ?? '0.0.0.0');
    exec_ctx.addString('ip.src.lat', ipInfo['ip.src.lat'] ?? '');
    exec_ctx.addString('ip.src.lon', ipInfo['ip.src.lon'] ?? '');
    exec_ctx.addString('ip.src.city', ipInfo['ip.src.city'] ?? '');
    exec_ctx.addString('ip.src.postal_code', ipInfo['ip.src.postal_code'] ?? '');
    exec_ctx.addString('ip.src.metro_code', ipInfo['ip.src.metro_code'] ?? '');
    exec_ctx.addString('ip.src.region', ipInfo['ip.src.region'] ?? '');
    exec_ctx.addString('ip.src.region_code', ipInfo['ip.src.region_code'] ?? '');
    exec_ctx.addNumber('ip.src.asnum', ipInfo['ip.src.asnum'] ?? 0);
    exec_ctx.addString('ip.src.continent', ipInfo['ip.src.continent'] ?? '');
    exec_ctx.addString('ip.src.country', ipInfo['ip.src.country'] ?? '');
    exec_ctx.addString(
      'ip.src.subdivision_1_iso_code',
      ipInfo['ip.src.subdivision_1_iso_code'] ?? '',
    );
    exec_ctx.addString(
      'ip.src.subdivision_2_iso_code',
      ipInfo['ip.src.subdivision_2_iso_code'] ?? '',
    );
    exec_ctx.addBoolean(
      'ip.src.is_in_european_union',
      ipInfo['ip.src.is_in_european_union'] ?? false,
    );
    exec_ctx.addNumber('ip.geoip.asnum', ipInfo['ip.src.asnum'] ?? 0);
    exec_ctx.addString('ip.geoip.continent', ipInfo['ip.src.continent'] ?? '');
    exec_ctx.addString('ip.geoip.country', ipInfo['ip.src.country'] ?? '');
    exec_ctx.addString(
      'ip.geoip.subdivision_1_iso_code',
      ipInfo['ip.src.subdivision_1_iso_code'] ?? '',
    );
    exec_ctx.addString(
      'ip.geoip.subdivision_2_iso_code',
      ipInfo['ip.src.subdivision_2_iso_code'] ?? '',
    );
    exec_ctx.addBoolean(
      'ip.geoip.is_in_european_union',
      ipInfo['ip.src.is_in_european_union'] ?? false,
    );
    exec_ctx.addBoolean('ssl', url.protocol === 'https:');
    // Argument and value fields for URIs
    exec_ctx.addStringMap('http.request.uri.args', paramsToMap(url.search));
    exec_ctx.addStringArray('http.request.uri.args.names', paramNamesToArray(url.search));
    exec_ctx.addStringArray('http.request.uri.args.values', paramValuesToArray(url.search));
    // Header fields
    exec_ctx.addStringMap('http.request.headers', headersToMap(req.headers));
    exec_ctx.addStringArray('http.request.headers.names', [...req.headers.keys()]);
    exec_ctx.addStringArray(
      'http.request.headers.values',
      ([] as string[]).concat(...req.headers.values()),
    );
    exec_ctx.addBoolean(
      'http.request.headers.truncated',
      req.cf['http.request.headers.truncated'] ?? false,
    );
    // Body fields
    exec_ctx.addString('http.request.body.raw', String(req.body ?? ''));
    exec_ctx.addBoolean(
      'http.request.body.truncated',
      req.cf['http.request.body.truncated'] ?? false,
    );
    let bodyParams: Map<string, string[]>;
    if ((req.headers.get('Content-Type') ?? '').startsWith('application/x-www-form-urlencoded')) {
      bodyParams = paramsToMap(String(req.body ?? ''));
    } else {
      bodyParams = new Map<string, string[]>();
    }
    exec_ctx.addNumber('http.request.body.size', String(req.body ?? '').length);
    exec_ctx.addStringMap('http.request.body.form', bodyParams);
    exec_ctx.addStringArray('http.request.body.form.names', [...bodyParams.keys()]);
    exec_ctx.addStringArray(
      'http.request.body.form.values',
      ([] as string[]).concat(...bodyParams.values()),
    );
    exec_ctx.addString('http.request.body.mime', req.headers.get('Content-Type') ?? '');
    // Dynamic fields
    exec_ctx.addString('cf.bot_management.ja3_hash', req.cf['cf.bot_management.ja3_hash'] ?? '');
    exec_ctx.addNumber('cf.bot_management.score', req.cf['cf.bot_management.score'] ?? 100);
    exec_ctx.addBoolean(
      'cf.bot_management.verified_bot',
      req.cf['cf.bot_management.verified_bot'] ?? false,
    );
    exec_ctx.addBoolean(
      'cf.bot_management.corporate_proxy',
      req.cf['cf.bot_management.corporate_proxy'] ?? false,
    );
    exec_ctx.addBoolean(
      'cf.bot_management.js_detection.passed',
      req.cf['cf.bot_management.js_detection.passed'] ?? false,
    );
    exec_ctx.addNumberArray(
      'cf.bot_management.detection_ids',
      req.cf['cf.bot_management.detection_ids'] ?? [],
    );
    exec_ctx.addBoolean(
      'cf.bot_management.static_resource',
      req.cf['cf.bot_management.static_resource'] ?? false,
    );
    exec_ctx.addNumber('cf.client_trust_score', req.cf['cf.client_trust_score'] ?? 100);
    exec_ctx.addString('cf.ray_id', req.cf['cf.ray_id'] ?? '');
    exec_ctx.addNumber('cf.threat_score', req.cf['cf.threat_score'] ?? 100);
    exec_ctx.addNumber('cf.edge.server_port', parsePort(req));
    exec_ctx.addBoolean('cf.client.bot', req.cf['cf.client.bot'] ?? false);
    exec_ctx.addString('cf.verified_bot_category', req.cf['cf.verified_bot_category'] ?? '');
    exec_ctx.addNumber('cf.waf.score', req.cf['cf.waf.score'] ?? 100);
    exec_ctx.addNumber('cf.waf.score.sqli', req.cf['cf.waf.score.sqli'] ?? 100);
    exec_ctx.addNumber('cf.waf.score.xss', req.cf['cf.waf.score.xss'] ?? 100);
    exec_ctx.addNumber('cf.waf.score.rce', req.cf['cf.waf.score.rce'] ?? 100);
    exec_ctx.addString('cf.waf.score.class', req.cf['cf.waf.score.class'] ?? '');
    exec_ctx.addString('cf.worker.upstream_zone', req.cf['cf.worker.upstream_zone'] ?? '');
    // IP Lists
    exec_ctx.setNeverMatchLists();
    exec_ctx.setupIntLists(lists.int);
    exec_ctx.setupIpLists(lists.ip);

    return exec_ctx;
  }

  constructor(
    private wirefilter: any,
    private scheme: any,
  ) {
    this.execCtx = wirefilter.wirefilter_create_execution_context(this.scheme);
  }

  get internalPointer() {
    return this.execCtx;
  }

  addNumber(name: string, value: number) {
    checkAdded(
      this.wirefilter.wirefilter_add_int_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        value,
      ),
      `Failed to add ${name}=${value} to the context`,
    );
  }

  addString(name: string, value: string) {
    checkAdded(
      this.wirefilter.wirefilter_add_bytes_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        wirefilterByteArray(value),
      ),
      `Failed to add ${name}=${value} to the context`,
    );
  }

  addBoolean(name: string, value: boolean) {
    checkAdded(
      this.wirefilter.wirefilter_add_bool_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        value,
      ),
      `Failed to add ${name}=${value} to the context`,
    );
  }

  addIpAddr(name: string, value: string) {
    const result = parseIp(value);

    if (result.type === 'v4') {
      checkAdded(
        this.wirefilter.wirefilter_add_ipv4_value_to_execution_context(
          this.execCtx,
          wirefilterString(name),
          result.ip,
        ),
        `Failed to add ${name}=${value} to the context`,
      );
    } else {
      // ipv6
      checkAdded(
        this.wirefilter.wirefilter_add_ipv6_value_to_execution_context(
          this.execCtx,
          wirefilterString(name),
          result.ip,
        ),
        `Failed to add ${name}=${value} to the context`,
      );
    }
  }

  addStringMap(name: string, value: Map<string, string[]>) {
    const arrayType = this.wirefilter.wirefilter_create_array_type(WIREFILTER_TYPE_BYTES);
    const mapValue = this.wirefilter.wirefilter_create_map(arrayType);
    value.forEach((mapVal, mapKey) => {
      const arr = this.wirefilter.wirefilter_create_array(WIREFILTER_TYPE_BYTES);
      mapVal.forEach((val, ind) => {
        checkAdded(
          this.wirefilter.wirefilter_add_bytes_value_to_array(arr, ind, wirefilterByteArray(val)),
          `Failed to add a ${val} to array`,
        );
      });
      checkAdded(
        this.wirefilter.wirefilter_add_array_value_to_map(mapValue, wirefilterString(mapKey), arr),
        `Failed to add ${mapKey} value to map`,
      );
    });
    checkAdded(
      this.wirefilter.wirefilter_add_map_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        mapValue,
      ),
      `Failed to add ${name}=${JSON.stringify(value)} to the context`,
    );
  }

  addStringArray(name: string, value: string[]) {
    const arr = this.wirefilter.wirefilter_create_array(WIREFILTER_TYPE_BYTES);
    value.forEach((val, ind) => {
      checkAdded(
        this.wirefilter.wirefilter_add_bytes_value_to_array(arr, ind, wirefilterByteArray(val)),
        `Failed to add a ${val} to array`,
      );
    });
    checkAdded(
      this.wirefilter.wirefilter_add_array_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        arr,
      ),
      `Failed to add ${name}=${JSON.stringify(value)} to the context`,
    );
  }

  addNumberArray(name: string, value: number[]) {
    const arr = this.wirefilter.wirefilter_create_array(WIREFILTER_TYPE_INT);
    value.forEach((val, ind) => {
      checkAdded(
        this.wirefilter.wirefilter_add_int_value_to_array(arr, ind, val),
        `Failed to add a ${val} to array`,
      );
    });
    checkAdded(
      this.wirefilter.wirefilter_add_array_value_to_execution_context(
        this.execCtx,
        wirefilterString(name),
        arr,
      ),
      `Failed to add ${name}=${JSON.stringify(value)} to the context`,
    );
  }

  setupIntLists(list: Lists['int']) {
    const map = this.buildList(WIREFILTER_TYPE_INT, list, (arr, i, value) => {
      checkAdded(
        this.wirefilter.wirefilter_add_int_value_to_array(arr, i, value),
        `Failed to add ${value} to array`,
      );
    });
    this.wirefilter.wirefilter_setup_int_lists(this.execCtx, map);
  }

  setupIpLists(list: Lists['ip']) {
    const map = this.buildList(WIREFILTER_TYPE_IP, list, (arr, i, value) => {
      const result = parseIp(value);
      switch (result.type) {
        case 'v4': {
          checkAdded(
            this.wirefilter.wirefilter_add_ipv4_value_to_array(arr, i, result.ip),
            `Failed to add ${value} to array`,
          );
          break;
        }
        case 'v6': {
          checkAdded(
            this.wirefilter.wirefilter_add_ipv6_value_to_array(arr, i, result.ip),
            `Failed to add ${value} to array`,
          );
          break;
        }
      }
    });
    this.wirefilter.wirefilter_setup_ip_lists(this.execCtx, map);
  }

  setNeverMatchLists() {
    checkAdded(
      this.wirefilter.set_all_lists_to_nevermatch(this.execCtx),
      "can't add nevermatch list",
    );
  }

  free() {
    this.wirefilter.wirefilter_free_execution_context(this.execCtx);
  }

  private buildList<T>(
    type: any,
    list: Record<string, T[]> | undefined,
    addToArray: (wirefilterArray: any, index: number, value: T) => void,
  ) {
    const arrType = this.wirefilter.wirefilter_create_array_type(type);
    const map = this.wirefilter.wirefilter_create_map(arrType);
    for (const [key, values] of Object.entries(list || {})) {
      const arr = this.wirefilter.wirefilter_create_array(type);
      values.forEach((value, i) => {
        addToArray(arr, i, value);
      });
      this.wirefilter.wirefilter_add_array_value_to_map(map, wirefilterString(key), arr);
    }
    return map;
  }
}
