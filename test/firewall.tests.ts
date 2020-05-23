import {Firewall, Request} from '../src';

describe("Firewall rule", () => {
    // see https://developers.cloudflare.com/firewall/cf-firewall-language/

    it("should match the entire cookie as a string", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.cookie != "gingersnaps"
        `);

        expect(rule.match(new Request('http://example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://example.org', {
            headers: [['Cookie', 'gingersnaps']]
        }))).toBeFalsy();
        expect(rule.match(new Request('http://example.org', {
            headers: [['Cookie', 'oatmeal']]
        }))).toBeTruthy();
    });

    it("should match the host name used in the full request URI", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.host eq "www.example.org"
        `);

        expect(rule.match(new Request('http://www.example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://www.example.com'))).toBeFalsy();
        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
    });

    it("should match the HTTP Referer header", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.referer eq "https://developer.example.org/en-US"
        `);

        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
        expect(rule.match(new Request('http://example.org', {
            headers: [['Referer', 'https://developer.example.org/en-US']]
        }))).toBeTruthy();
        expect(rule.match(new Request('http://example.org', {
            headers: [['Referer', 'https://example.com']]
        }))).toBeFalsy();
    });

    it("should match the full URI", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.full_uri == "https://www.example.org/articles/index?section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it("should match the HTTP method, in uppercase", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.method eq "GET"
        `);

        expect(rule.match(new Request('http://example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://example.org', {
            method: 'POST'
        }))).toBeFalsy();
    });

    it("should match the absolute URI of the request", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.uri == "/articles/index?section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it("should match the path of the request", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.uri.path == "/articles/index"
        `);

        expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it("should match the whole query string, minus the ? delimiter", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.uri.query == "section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it("should match the HTTP user agent", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.user_agent == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36']]
        }))).toBeTruthy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36']]
        }))).toBeFalsy();
    });

    it("should match the version of the protocol used for the request", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.request.version == 1
        `);

        expect(rule.match(new Request('https://example.org'))).toBeTruthy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-http.request.version', 'HTTP/3']]
        }))).toBeFalsy();
    });

    it("should match the full X-Forwarded-For HTTP header", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            http.x_forwarded_for == "203.0.113.195, 70.41.3.18"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['X-Forwarded-For', '203.0.113.195, 70.41.3.18']]
        }))).toBeTruthy();
    });

    it("should match the client TCP IP address", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.src == 93.184.216.34 or
            ip.src == 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.src', '93.184.216.34']]
        }))).toBeTruthy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.src', '1.2.3.4']]
        }))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.src', '2001:0db8:85a3:0000:0000:8a2e:0370:7334']]
        }))).toBeTruthy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.src', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']]
        }))).toBeFalsy();
    });

    it("should match the 16- or 32-bit ASN associated with the request", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.asnum == 1234
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.asnum', '1234']]
        }))).toBeTruthy();
    });

    it("should match the continent code for this location Possible codes", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.continent == "EU"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.continent', 'EU']]
        }))).toBeTruthy();
    });

    it("should match the 2-letter country code in ISO 3166-1 Alpha 2 format", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.country == "RU"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.country', 'RU']]
        }))).toBeTruthy();
    });

    it("should match the ISO 3166-2 code for the first level region associated with the IP address.", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.subdivision_1_iso_code == "GB-ENG"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.subdivision_1_iso_code', 'GB-ENG']]
        }))).toBeTruthy();
    });

    it("should match the ISO 3166-2 code for the second level region associated with the IP address.", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.subdivision_2_iso_code == "GB-SWK"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.subdivision_2_iso_code', 'GB-SWK']]
        }))).toBeTruthy();
    });

    it("should match when the request originates from an EU country", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ip.geoip.is_in_european_union
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.is_in_european_union', 'true']]
        }))).toBeTruthy();
    });

    it("should match when the HTTP connection to the client is encrypted", () => {
        const firewall = new Firewall()
        const rule = firewall.createFirewallRule(`
            ssl
        `);

        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org'))).toBeTruthy();
    });
});
