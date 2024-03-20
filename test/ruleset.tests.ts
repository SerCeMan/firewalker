import { Firewall, Request } from '../src';
import { FirewallRuleset } from '../src/firewall';

const firewall = new Firewall();
let ruleset: FirewallRuleset;

beforeEach(() => {
    ruleset = firewall.createRuleSet();
});

describe('Multi-rule testing', () => {
    beforeEach(() => {
        ruleset
            .addRule({
                id: 'blockCookies',
                expression: 'http.cookie != "gingersnaps"',
                action: { type: 'block' }
            })
            .addRule({
                id: 'logReferrers',
                expression: 'http.referer eq "https://developer.example.org/en-US"',
                action: { type: 'log' }
            })
            .addRule({
                id: 'fooSkips',
                expression: 'http.request.uri.path eq "/test/foo"',
                action: { type: 'skip', ruleset: 'current' }
            })
            .addRule({
                id: 'barSkips',
                expression: 'http.request.uri.path eq "/test/bar"',
                action: { type: 'skip', phases: ['http_ratelimit'], products: ['bic'] }
            })
            .addRule({
                id: 'testChallenges',
                expression: 'http.request.uri.path matches "^/test/.*"',
                action: { type: 'managed_challenge' },
            });
    });

    it('blocks expected request without cookie', () => {
        const request = new Request('http://example.org', {
            headers: [
                ['Cookie', 'oatmeal'],
                ['Referer', 'https://developer.example.org/en-US'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.terminalAction).toMatchObject({
            ruleId: 'blockCookies',
            action: { type: 'block', },
        });
    });

    it('logs rules in results', () => {
        const request = new Request('http://example.org/', {
            headers: [
                ['Cookie', 'gingersnaps'],
                ['Referer', 'https://developer.example.org/en-US'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.loggedRules).toStrictEqual(['logReferrers']);
    });

    it('challenges as expected', () => {
        const request = new Request('http://example.org/test/baz', {
            headers: [
                ['Cookie', 'gingersnaps'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.terminalAction).toMatchObject({
            ruleId: 'testChallenges',
            action: { type: 'managed_challenge' },
        });
    });

    it('skip current ruleset works as expected', () => {
        const request = new Request('http://example.org/test/foo', {
            headers: [
                ['Cookie', 'gingersnaps'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            action: { type: 'skip' },
        });
    });

    it('non-matching request reports no match', () => {
        const request = new Request('http://example.org/', {
            headers: [
                ['Cookie', 'gingersnaps'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeFalsy();
        expect(result.terminalAction).toMatchObject({
            action: { type: 'no_match' }
        });
    });

    it('skips phases and products works as expected', () => {
        const request = new Request('http://example.org/test/bar', {
            headers: [
                ['Cookie', 'gingersnaps'],
            ]
        });
        const result = ruleset.matchRequest(request);
        expect(result.skippedPhases).toContain('http_ratelimit');
        expect(result.skippedProducts).toContain('bic');
    });
});

describe('rules with lists', () => {
    beforeEach(() => {
        ruleset
            .setDefaultLists({
                int: {
                    'bypass_asns': [123],
                    'bad_asns': [456],
                },
                ip: {
                    'bypass_ips': ['10.0.0.1'],
                    'bad_ips': ['11.0.0.1'],
                }
            })
            .addRule({
                id: 'bypassAsns',
                expression: 'ip.geoip.asnum in $bypass_asns',
                action: {
                    type: 'skip',
                    ruleset: 'current',
                }
            })
            .addRule({
                id: 'blockAsns',
                expression: 'ip.geoip.asnum in $bad_asns',
                action: { type: 'block' },
            })
            .addRule({
                id: 'bypassIps',
                expression: 'ip.src in $bypass_ips',
                action: {
                    type: 'skip',
                    ruleset: 'current',
                }
            })
            .addRule({
                id: 'blockIps',
                expression: 'ip.src in $bad_ips',
                action: { type: 'block' },
            })
            .addRule({
                id: 'challengeRemaining',
                expression: 'http.request.uri.path matches "^/"',
                action: { type: 'managed_challenge' }
            });
    });

    it('challenges when not in lists', () => {
        const request = new Request('https://example.org');
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            ruleId: 'challengeRemaining',
            action: { type: 'managed_challenge', }
        });
    });

    it('bypasses when asn in list', () => {
        const request = new Request('https://example.org', { cf: { 'ip.geoip.asnum': 123 } });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            action: { type: 'skip', }
        });
    });

    it('blocks bad asn', () => {
        const request = new Request('https://example.org', { cf: { 'ip.geoip.asnum': 456 } });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            ruleId: 'blockAsns',
            action: { type: 'block', }
        });
    });

    it('bypasses when ip in list', () => {
        const request = new Request('https://example.org', { cf: { 'ip.src': '10.0.0.1' } });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            action: { type: 'skip', }
        });
    });

    it('blocks bad asn', () => {
        const request = new Request('https://example.org', { cf: { 'ip.src': '11.0.0.1' } });
        const result = ruleset.matchRequest(request);
        expect(result.terminatedEarly).toBeTruthy();
        expect(result.terminalAction).toMatchObject({
            ruleId: 'blockIps',
            action: { type: 'block', }
        });
    });
});