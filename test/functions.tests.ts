import {Firewall, Request} from '../src';

describe('Transformation function', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('any function returns true if the condition is true for any of the values', () => {
        const rule = firewall.createFirewallRule(`
            any(http.request.headers.values[*] contains "java")
        `);

        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
        expect(rule.match(new Request('http://example.org', {
            headers: [
                ['x-lang-1', 'kotlin'],
                ['x-lang-2', 'typescript'],
            ]
        }))).toBeFalsy();
        expect(rule.match(new Request('http://example.org', {
            headers: [
                ['x-header1', 'kotlin'],
                ['x-header2', 'java'],
            ]
        }))).toBeTruthy();
    });

    it('all function returns true if the condition is true for any of the values', () => {
        const rule = firewall.createFirewallRule(`
            all(http.request.headers.values[*] contains "java")
        `);

        expect(rule.match(new Request('http://example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://example.org', {
            headers: [
                ['x-lang-1', 'java'],
                ['x-lang-2', 'typescript'],
            ]
        }))).toBeFalsy();
        expect(rule.match(new Request('http://example.org', {
            headers: [
                ['x-header1', 'java'],
                ['x-header2', 'java'],
            ]
        }))).toBeTruthy();
    });

    it('len Returns the byte length of a String or Bytes field', () => {
        const rule = firewall.createFirewallRule(`
            len(http.host) == 11
        `);

        expect(rule.match(new Request('http://example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://acme.com'))).toBeFalsy();
    });

    it('lower converts a string field to lowercase', () => {
        const rule = firewall.createFirewallRule(`
            lower(http.request.uri) == "/login"
        `);

        expect(rule.match(new Request('http://example.org/LOGIN'))).toBeTruthy();
    });

    it('url_decode decodes a URL formatted string.', () => {
        const rule = firewall.createFirewallRule(`
            url_decode(http.request.uri) == "/hello firewalker world!"
        `);

        expect(rule.match(new Request('http://example.org/hello%20firewalker%20world%21'))).toBeTruthy();
    });
});
