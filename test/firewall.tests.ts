import {Firewall, Request} from '../src';
import {URLSearchParams} from 'url';

// see https://developers.cloudflare.com/firewall/cf-firewall-language/

describe('Standard fields', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('should match the entire cookie as a string', () => {
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

    it('should match the host name used in the full request URI', () => {
        const rule = firewall.createFirewallRule(`
            http.host eq "www.example.org"
        `);

        expect(rule.match(new Request('http://www.example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://www.example.com'))).toBeFalsy();
        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
    });

    it('should match the HTTP Referer header', () => {
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

    it('should match the full URI', () => {
        const rule = firewall.createFirewallRule(`
            http.request.full_uri == "https://www.example.org/articles/index?section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it('should match the HTTP method, in uppercase', () => {
        const rule = firewall.createFirewallRule(`
            http.request.method eq "GET"
        `);

        expect(rule.match(new Request('http://example.org'))).toBeTruthy();
        expect(rule.match(new Request('http://example.org', {
            method: 'POST'
        }))).toBeFalsy();
    });

    it('should match the absolute URI of the request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri == "/articles/index?section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it('should match the path of the request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri.path == "/articles/index"
        `);

        expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it('should match the whole query string, minus the ? delimiter', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri.query == "section=539061&expand=comments"
        `);

        expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
        expect(rule.match(new Request(
            'https://www.example.org/articles/index?section=539061&expand=comments'
        ))).toBeTruthy();
    });

    it('should match the HTTP user agent', () => {
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

    it('should match the version of the protocol used for the request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.version == 1
        `);

        expect(rule.match(new Request('https://example.org'))).toBeTruthy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-http.request.version', 'HTTP/3']]
        }))).toBeFalsy();
    });

    it('should match the full X-Forwarded-For HTTP header', () => {
        const rule = firewall.createFirewallRule(`
            http.x_forwarded_for == "203.0.113.195, 70.41.3.18"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['X-Forwarded-For', '203.0.113.195, 70.41.3.18']]
        }))).toBeTruthy();
    });

    it('should match the client TCP IP address', () => {
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

    it('should match the 16- or 32-bit ASN associated with the request', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.asnum == 1234
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.asnum', '1234']]
        }))).toBeTruthy();
    });

    it('should match the continent code for this location Possible codes', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.continent == "EU"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.continent', 'EU']]
        }))).toBeTruthy();
    });

    it('should match the 2-letter country code in ISO 3166-1 Alpha 2 format', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.country == "RU"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.country', 'RU']]
        }))).toBeTruthy();
    });

    it('should match the ISO 3166-2 code for the first level region associated with the IP address.', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.subdivision_1_iso_code == "GB-ENG"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.subdivision_1_iso_code', 'GB-ENG']]
        }))).toBeTruthy();
    });

    it('should match the ISO 3166-2 code for the second level region associated with the IP address.', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.subdivision_2_iso_code == "GB-SWK"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.subdivision_2_iso_code', 'GB-SWK']]
        }))).toBeTruthy();
    });

    it('should match when the request originates from an EU country', () => {
        const rule = firewall.createFirewallRule(`
            ip.geoip.is_in_european_union
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-ip.geoip.is_in_european_union', 'true']]
        }))).toBeTruthy();
    });

    it('should match when the HTTP connection to the client is encrypted', () => {
        const rule = firewall.createFirewallRule(`
            ssl
        `);

        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org'))).toBeTruthy();
    });
});

describe('Argument and value fields for URIs', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('should match the HTTP URI arguments represented in a map', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri.args["search"][0] == "red+apples" or
            http.request.uri.args["search"][1] == "red+apples"
        `);
        // TODO: support transformation functions
        // const rule = firewall.createFirewallRule(`
        //     http.request.uri.args["search"][0] == "red+apples"
        // `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org?search=red+apples'))).toBeTruthy();
        expect(rule.match(new Request('https://example.org?search=something+else&search=red+apples'))).toBeTruthy();
        expect(rule.match(new Request('https://example.org?search=nothing&search2=nothing2'))).toBeFalsy();
    });

    it('should match the names of arguments in the HTTP URI query string', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri.args.names[0] == "search"
        `);
        // TODO: support transformation functions
        // const rule = firewall.createFirewallRule(`
        //     any(http.request.uri.args["search"][*] == "red+apples")
        // `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org?search=red+apples'))).toBeTruthy();
    });

    it('should match the values of arguments in the HTTP URI query string', () => {
        const rule = firewall.createFirewallRule(`
            http.request.uri.args.values[0] == "red+apples"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org?search=red+apples'))).toBeTruthy();
    });
});

describe('Header fields', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('should match the HTTP request headers represented in a map', () => {
        const rule = firewall.createFirewallRule(`
            http.request.headers["content-type"][0] == "application/json"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['Content-Type', 'application/json']]
        }))).toBeTruthy();
    });

    it('should match the values of headers in the HTTP request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.headers.values[0] == "application/json"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['Content-Type', 'application/json']]
        }))).toBeTruthy();
    });

    it('should match the names of headers in the HTTP request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.headers.names[0] == "content-type"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['Content-Type', 'application/json']]
        }))).toBeTruthy();
    });

    it('should match when HTTP request contained too many headers', () => {
        const rule = firewall.createFirewallRule(`
            http.request.headers.truncated
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-http.request.headers.truncated', 'true']]
        }))).toBeTruthy();
    });
});

describe('Body fields', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('should match the string representing the unaltered HTTP request body', () => {
        const rule = firewall.createFirewallRule(`
            http.request.body.raw == "{\\"example\\":\\"payload\\"}"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            method: 'POST',
            body: JSON.stringify({'example': 'payload'})
        }))).toBeTruthy();
    });

    it('should match if the HTTP request body was too long', () => {
        const rule = firewall.createFirewallRule(`
            http.request.body.truncated
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-http.request.body.truncated', 'true']]
        }))).toBeTruthy();
    });

    it('should match HTTP body represented in a map (application/x-www-form-urlencoded)', () => {
        const rule = firewall.createFirewallRule(`
            http.request.body.form["username"][0] == "admin"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            body: new URLSearchParams('email=test@example.com&username=admin'),
            method: 'POST'
        }))).toBeTruthy();
    });

    it('should match the names of form fields in the HTTP request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.body.form.names[0] == "email" and 
            http.request.body.form.names[1] == "username"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            body: new URLSearchParams('email=test@example.com&username=admin'),
            method: 'POST'
        }))).toBeTruthy();
    });

    it('should match the values of form fields in the HTTP request', () => {
        const rule = firewall.createFirewallRule(`
            http.request.body.form.values[0] == "test%40example.com" and
            http.request.body.form.values[1] == "admin"
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            body: new URLSearchParams('email=test@example.com&username=admin'),
            method: 'POST'
        }))).toBeTruthy();
    });
});

describe('Dynamic fields', () => {
    let firewall: Firewall;

    beforeEach(() => {
        firewall = new Firewall();
    });

    it('should match the request originates from a known bot or crawler, regardless of good or bad intent', () => {
        const rule = firewall.createFirewallRule(`
            cf.bot_management.verified_bot
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-cf.bot_management.verified_bot', 'true']]
        }))).toBeTruthy();
    });

    it('should match the threat score from 0–100, where 0 indicates low risk', () => {
        const rule = firewall.createFirewallRule(`
            cf.threat_score < 50
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-cf.threat_score', '20']]
        }))).toBeTruthy();
    });

    it('should match the bot management score used to measure if the request is from a human or a script.', () => {
        const rule = firewall.createFirewallRule(`
            cf.bot_management.score < 50
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-cf.bot_management.score', '20']]
        }))).toBeTruthy();
    });

    it('should match the port number at which Cloudflare\'s network received the request.', () => {
        const rule = firewall.createFirewallRule(`
            cf.edge.server_port == 22 or 
            cf.edge.server_port == 443
        `);

        expect(rule.match(new Request('http://example.org'))).toBeFalsy();
        expect(rule.match(new Request('ssh://example.org:22'))).toBeTruthy();
        expect(rule.match(new Request('https://example.org'))).toBeTruthy();
    });

    it('should match when a client is a known good bo', () => {
        const rule = firewall.createFirewallRule(`
            cf.client.bot
        `);

        expect(rule.match(new Request('https://example.org'))).toBeFalsy();
        expect(rule.match(new Request('https://example.org', {
            headers: [['x-cf.client.bot', 'true']]
        }))).toBeTruthy();
    });

});
