import { Firewall, Request } from '../src';
import { URLSearchParams } from 'url';

// see https://developers.cloudflare.com/firewall/cf-firewall-language/

describe('Standard fields', () => {
  let firewall: Firewall;

  beforeEach(() => {
    firewall = new Firewall();
  });

  it('should match the entire cookie as a string', () => {
    const rule = firewall.createRule(`
            http.cookie != "gingersnaps"
        `);

    expect(rule.match(new Request('http://example.org'))).toBeTruthy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Cookie', 'gingersnaps']],
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Cookie', 'oatmeal=false']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the host name used in the full request URI', () => {
    const rule = firewall.createRule(`
            http.host eq "www.example.org"
        `);

    expect(rule.match(new Request('http://www.example.org'))).toBeTruthy();
    expect(rule.match(new Request('http://www.example.com'))).toBeFalsy();
    expect(rule.match(new Request('http://example.org'))).toBeFalsy();
  });

  it('should match the HTTP Referer header', () => {
    const rule = firewall.createRule(`
            http.referer eq "https://developer.example.org/en-US"
        `);

    expect(rule.match(new Request('http://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Referer', 'https://developer.example.org/en-US']],
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Referer', 'https://example.com']],
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the full URI', () => {
    const rule = firewall.createRule(`
            http.request.full_uri == "https://www.example.org/articles/index?section=539061&expand=comments"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://www.example.org/articles/index?section=539061&expand=comments'),
      ),
    ).toBeTruthy();
  });

  it('should match the HTTP method, in uppercase', () => {
    const rule = firewall.createRule(`
            http.request.method eq "GET"
        `);

    expect(rule.match(new Request('http://example.org'))).toBeTruthy();
    expect(
      rule.match(
        new Request('http://example.org', {
          method: 'POST',
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the unpacked cookie string', () => {
    const rule = firewall.createRule(`
            any(http.request.cookies["gingersnaps"][*] eq "true")
        `);

    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Cookie', 'gingersnaps=true']],
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Cookie', 'gingersnaps=false;ginger snaps=true']],
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [['Cookie', 'gingersnaps=false;gingersnaps=true']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the absolute URI of the request', () => {
    const rule = firewall.createRule(`
            http.request.uri == "/articles/index?section=539061&expand=comments"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://www.example.org/articles/index?section=539061&expand=comments'),
      ),
    ).toBeTruthy();
  });

  it('should match the path of the request', () => {
    const rule = firewall.createRule(`
            http.request.uri.path == "/articles/index"
        `);

    expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://www.example.org/articles/index?section=539061&expand=comments'),
      ),
    ).toBeTruthy();
  });

  it('should match the path extension of the request', () => {
    const rule = firewall.createRule(`
            http.request.uri.path.extension eq "cfrule"
        `);

    expect(rule.match(new Request('https://example.org/test.cfrule'))).toBeTruthy();
    expect(rule.match(new Request('https://example.org/test.test.cfrule'))).toBeTruthy();
    expect(rule.match(new Request('https://example.org/test.CFRULE'))).toBeTruthy();
    expect(rule.match(new Request('https://example.org/.cfrule'))).toBeFalsy();
    expect(rule.match(new Request('https://example.org/.cfrule.'))).toBeFalsy();
  });

  it('should match the whole query string, minus the ? delimiter', () => {
    const rule = firewall.createRule(`
            http.request.uri.query == "section=539061&expand=comments"
        `);

    expect(rule.match(new Request('https://example.org/test'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://www.example.org/articles/index?section=539061&expand=comments'),
      ),
    ).toBeTruthy();
  });

  it('should match the HTTP user agent', () => {
    const rule = firewall.createRule(`
            http.user_agent == "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [
            [
              'User-Agent',
              'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
            ],
          ],
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [
            [
              'User-Agent',
              'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
            ],
          ],
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the version of the protocol used for the request', () => {
    const rule = firewall.createRule(`
            http.request.version == 1
        `);

    expect(rule.match(new Request('https://example.org'))).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: {
            'http.request.version': 2,
          },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the full X-Forwarded-For HTTP header', () => {
    const rule = firewall.createRule(`
            http.x_forwarded_for == "203.0.113.195, 70.41.3.18"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['X-Forwarded-For', '203.0.113.195, 70.41.3.18']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the client TCP IP address', () => {
    const rule = firewall.createRule(`
            ip.src == 93.184.216.34 or
            ip.src == 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src': '93.184.216.34' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src': '1.2.3.4' },
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src': '2001:0db8:85a3:0000:0000:8a2e:0370:7334' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the latitude of the ip address', () => {
    const rule = firewall.createRule('ip.src.lat eq "-33.8853"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.lat': '-33.8853' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.lat': '33.8853' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the longitude of the ip address', () => {
    const rule = firewall.createRule('ip.src.lon eq "151.2114"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.lon': '151.2114' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.lon': '33.8853' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the city of the ip address', () => {
    const rule = firewall.createRule('ip.src.city eq "Sydney"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.city': 'Sydney' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.city': 'Melbourne' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the postal code of the ip address', () => {
    const rule = firewall.createRule('ip.src.postal_code eq "2000"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.postal_code': '2000' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.postal_code': '3000' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the metro code of the ip address', () => {
    const rule = firewall.createRule('ip.src.metro_code eq "635"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.metro_code': '635' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.metro_code': '3000' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the region of the ip address', () => {
    const rule = firewall.createRule('ip.src.region eq "New South Wales"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.region': 'New South Wales' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.region': 'Victoria' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the region_code of the ip address', () => {
    const rule = firewall.createRule('ip.src.region_code eq "NSW"');

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.region_code': 'NSW' },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.src.region_code': 'VIC' },
        }),
      ),
    ).toBeFalsy();
  });

  it('should match the 16- or 32-bit ASN associated with the request', () => {
    const rule = firewall.createRule(`
            ip.geoip.asnum == 1234 && ip.src.asnum == 1234
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.asnum': 1234 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the continent code for this location Possible codes', () => {
    const rule = firewall.createRule(`
            ip.geoip.continent == "EU" && ip.src.continent == "EU"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.continent': 'EU' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the 2-letter country code in ISO 3166-1 Alpha 2 format', () => {
    const rule = firewall.createRule(`
            ip.geoip.country == "RU" && ip.src.country == "RU"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.country': 'RU' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the ISO 3166-2 code for the first level region associated with the IP address.', () => {
    const rule = firewall.createRule(`
            ip.geoip.subdivision_1_iso_code == "GB-ENG"
            && ip.src.subdivision_1_iso_code == "GB-ENG"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.subdivision_1_iso_code': 'GB-ENG' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the ISO 3166-2 code for the second level region associated with the IP address.', () => {
    const rule = firewall.createRule(`
            ip.geoip.subdivision_2_iso_code == "GB-SWK"
            && ip.src.subdivision_2_iso_code == "GB-SWK"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.subdivision_2_iso_code': 'GB-SWK' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match when the request originates from an EU country', () => {
    const rule = firewall.createRule(`
            ip.geoip.is_in_european_union &&
            ip.src.is_in_european_union
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'ip.geoip.is_in_european_union': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match when the HTTP connection to the client is encrypted', () => {
    const rule = firewall.createRule(`
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
    const rule = firewall.createRule(`
            http.request.uri.args["search"][0] == "red+apples" or
            http.request.uri.args["search"][1] == "red+apples"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(rule.match(new Request('https://example.org?search=red+apples'))).toBeTruthy();
    expect(
      rule.match(new Request('https://example.org?search=something+else&search=red+apples')),
    ).toBeTruthy();
    expect(
      rule.match(new Request('https://example.org?search=nothing&search2=nothing2')),
    ).toBeFalsy();
  });

  it('should match the names of arguments in the HTTP URI query string', () => {
    const rule = firewall.createRule(`
            http.request.uri.args.names[0] == "search"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(rule.match(new Request('https://example.org?search=red+apples'))).toBeTruthy();
  });

  it('should match the values of arguments in the HTTP URI query string', () => {
    const rule = firewall.createRule(`
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
    const rule = firewall.createRule(`
            http.request.headers["content-type"][0] == "application/json"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['Content-Type', 'application/json']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the values of headers in the HTTP request', () => {
    const rule = firewall.createRule(`
            http.request.headers.values[0] == "application/json"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['Content-Type', 'application/json']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the names of headers in the HTTP request', () => {
    const rule = firewall.createRule(`
            http.request.headers.names[0] == "content-type"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['Content-Type', 'application/json']],
        }),
      ),
    ).toBeTruthy();
  });

  it('should match when HTTP request contained too many headers', () => {
    const rule = firewall.createRule(`
            http.request.headers.truncated
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'http.request.headers.truncated': true },
        }),
      ),
    ).toBeTruthy();
  });
});

describe('Body fields', () => {
  let firewall: Firewall;

  beforeEach(() => {
    firewall = new Firewall();
  });

  it('should match the string representing the unaltered HTTP request body', () => {
    const rule = firewall.createRule(`
            http.request.body.raw == "{\\"example\\":\\"payload\\"}"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          method: 'POST',
          body: JSON.stringify({ example: 'payload' }),
        }),
      ),
    ).toBeTruthy();
  });

  it('should match if the HTTP request body was too long', () => {
    const rule = firewall.createRule(`
            http.request.body.truncated
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'http.request.body.truncated': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match based on the computed body size', () => {
    const rule = firewall.createRule(`
            http.request.body.size < 10
        `);

    expect(
      rule.match(
        new Request('https://example.org', {
          method: 'POST',
          body: 'large body',
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          method: 'POST',
          body: 'tiny body',
        }),
      ),
    ).toBeTruthy();
  });

  it('should match HTTP body represented in a map (application/x-www-form-urlencoded)', () => {
    const rule = firewall.createRule(`
            http.request.body.form["username"][0] == "admin"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          body: new URLSearchParams('email=test@example.com&username=admin'),
          method: 'POST',
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the names of form fields in the HTTP request', () => {
    const rule = firewall.createRule(`
            http.request.body.form.names[0] == "email" and
            http.request.body.form.names[1] == "username"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          body: new URLSearchParams('email=test@example.com&username=admin'),
          method: 'POST',
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the values of form fields in the HTTP request', () => {
    const rule = firewall.createRule(`
            http.request.body.form.values[0] == "test%40example.com" and
            http.request.body.form.values[1] == "admin"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          body: new URLSearchParams('email=test@example.com&username=admin'),
          method: 'POST',
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the mime type provided in the Content-Type', () => {
    const rule = firewall.createRule('http.request.body.mime eq "application/json"');

    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['Content-Type', 'application/json']],
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          headers: [['Content-Type', 'application/javascript']],
        }),
      ),
    ).toBeFalsy();
  });
});

describe('Dynamic fields', () => {
  let firewall: Firewall;

  beforeEach(() => {
    firewall = new Firewall();
  });

  it('should match the request originates from a known bot or crawler, regardless of good or bad intent', () => {
    const rule = firewall.createRule(`
            cf.bot_management.verified_bot
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.verified_bot': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request originates from a corporate proxy', () => {
    const rule = firewall.createRule(`
            cf.bot_management.corporate_proxy
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.corporate_proxy': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with a known JA3 hash', () => {
    const rule = firewall.createRule(`
            cf.bot_management.ja3_hash == "388a2f0ab9bd102d45826cc2af4e183a"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.ja3_hash': '388a2f0ab9bd102d45826cc2af4e183a' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with js detection passed', () => {
    const rule = firewall.createRule(`
            cf.bot_management.js_detection.passed
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.js_detection.passed': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with with correct detection_ids', () => {
    const rule = firewall.createRule(`
            any(cf.bot_management.detection_ids[*] eq 1234567)
        `);

    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.detection_ids': [7654321] },
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.detection_ids': [1234567, 7654321] },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match when the request has a specific ray id', () => {
    const rule = firewall.createRule(`
            cf.ray_id eq "81b00169da4b55f0"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.ray_id': '81b00169da4b55f0' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the threat score from 0–100, where 0 indicates low risk', () => {
    const rule = firewall.createRule(`
            cf.threat_score < 50
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.threat_score': 0 },
        }),
      ),
    ).toBeTruthy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.threat_score': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the bot management score used to measure if the request is from a human or a script.', () => {
    const rule = firewall.createRule(`
            cf.bot_management.score < 50
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.score': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request marked as a static resource', () => {
    const rule = firewall.createRule(`
            cf.bot_management.static_resource
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.bot_management.static_resource': true },
        }),
      ),
    ).toBeTruthy();
  });

  it("should match the port number at which Cloudflare's network received the request.", () => {
    const rule = firewall.createRule(`
            cf.edge.server_port == 22 or
            cf.edge.server_port == 443
        `);

    expect(rule.match(new Request('http://example.org'))).toBeFalsy();
    expect(rule.match(new Request('ssh://example.org:22'))).toBeTruthy();
    expect(rule.match(new Request('https://example.org'))).toBeTruthy();
  });

  it('should match when a client is a known good bot', () => {
    const rule = firewall.createRule(`
            cf.client.bot
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.client.bot': true },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match when the request is from a search crawler', () => {
    const rule = firewall.createRule(`
            cf.verified_bot_category eq "Search Crawler"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.verified_bot_category': 'Search Crawler' },
        }),
      ),
    ).toBeTruthy();
  });
  it('should match the request with low overall waf score', () => {
    const rule = firewall.createRule(`
            cf.waf.score le 20
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.waf.score': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with low sqli waf score', () => {
    const rule = firewall.createRule(`
            cf.waf.score.sqli le 20
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.waf.score.sqli': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with low xss waf score', () => {
    const rule = firewall.createRule(`
            cf.waf.score.xss le 20
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.waf.score.xss': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with low rce waf score', () => {
    const rule = firewall.createRule(`
            cf.waf.score.rce le 20
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.waf.score.rce': 20 },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with likely attack class', () => {
    const rule = firewall.createRule(`
            cf.waf.score.class eq "likely_attack"
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.waf.score.class': 'likely_attack' },
        }),
      ),
    ).toBeTruthy();
  });

  it('should match the request with upstream zone populated', () => {
    const rule = firewall.createRule(`
            !cf.worker.upstream_zone eq ""
        `);

    expect(rule.match(new Request('https://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('https://example.org', {
          cf: { 'cf.worker.upstream_zone': 'example.com' },
        }),
      ),
    ).toBeTruthy();
  });
});

describe('Transformation function', () => {
  let firewall: Firewall;

  beforeEach(() => {
    firewall = new Firewall();
  });

  it('any function returns true if the condition is true for any of the values', () => {
    const rule = firewall.createRule(`
            any(http.request.headers.values[*] contains "java")
        `);

    expect(rule.match(new Request('http://example.org'))).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [
            ['x-lang-1', 'kotlin'],
            ['x-lang-2', 'typescript'],
          ],
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [
            ['x-header1', 'kotlin'],
            ['x-header2', 'java'],
          ],
        }),
      ),
    ).toBeTruthy();
  });

  it('all function returns true if the condition is true for any of the values', () => {
    const rule = firewall.createRule(`
            all(http.request.headers.values[*] contains "java")
        `);

    expect(rule.match(new Request('http://example.org'))).toBeTruthy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [
            ['x-lang-1', 'java'],
            ['x-lang-2', 'typescript'],
          ],
        }),
      ),
    ).toBeFalsy();
    expect(
      rule.match(
        new Request('http://example.org', {
          headers: [
            ['x-header1', 'java'],
            ['x-header2', 'java'],
          ],
        }),
      ),
    ).toBeTruthy();
  });

  it('len Returns the byte length of a String or Bytes field', () => {
    const rule = firewall.createRule(`
            len(http.host) == 11
        `);

    expect(rule.match(new Request('http://example.org'))).toBeTruthy();
    expect(rule.match(new Request('http://acme.com'))).toBeFalsy();
  });

  it('lower converts a string field to lowercase', () => {
    const rule = firewall.createRule(`
            lower(http.request.uri) == "/login"
        `);

    expect(rule.match(new Request('http://example.org/LOGIN'))).toBeTruthy();
  });

  it('url_decode decodes a URL formatted string.', () => {
    const rule = firewall.createRule(`
            url_decode(http.request.uri) == "/hello firewalker world!"
        `);

    expect(
      rule.match(new Request('http://example.org/hello%20firewalker%20world%21')),
    ).toBeTruthy();
  });

  it('starts_with returns true when the field value starts with the string', () => {
    const rule = firewall.createRule(`
            starts_with(http.host,"example")
        `);

    expect(rule.match(new Request('http://example.org/hello'))).toBeTruthy();
    expect(rule.match(new Request('http://fake-example.org/hello'))).toBeFalsy();
  });

  it('ends_with returns true when the field value end with the string', () => {
    const rule = firewall.createRule(`
            ends_with(http.host,"org")
        `);

    expect(rule.match(new Request('http://example.org/hello'))).toBeTruthy();
    expect(rule.match(new Request('http://example.com/hello'))).toBeFalsy();
  });

  it('remove_bytes removes values from strings', () => {
    const rule = firewall.createRule(`
            remove_bytes(http.host,".e") == "xamplorg"
        `);

    expect(rule.match(new Request('http://example.org/hello'))).toBeTruthy();
  });
  it('substring correctly slices a string', () => {
    const rule = firewall.createRule(`
            substring(http.request.uri,-2) == "jk" and
            substring(http.request.uri,2) == "sdfghjk" and
            substring(http.request.uri,2,5) == "sdf" 
        `);

    expect(rule.match(new Request('http://example.org/asdfghjk'))).toBeTruthy();
  });
});

describe('Lists', () => {
  let firewall: Firewall;
  const lists = {
    int: {
      office_asns: [2345],
    },
    ip: {
      office_network: ['10.0.0.1'],
    },
  };

  beforeEach(() => {
    firewall = new Firewall();
  });

  it('an IP is not in an IP list', () => {
    const rule = firewall.createRule(
      `
            (ip.src in $office_network)
        `,
      lists,
    );

    expect(
      rule.match(
        new Request('http://example.org', {
          cf: { 'ip.src': '1.2.3.4' },
        }),
      ),
    ).toBeFalsy();
  });

  it('an IP is in an IP list', () => {
    const rule = firewall.createRule(
      `
            (ip.src in $office_network)
        `,
      lists,
    );

    expect(
      rule.match(
        new Request('http://example.org', {
          cf: { 'ip.src': '10.0.0.1' },
        }),
      ),
    ).toBeTruthy();
  });

  it('an ASN is not in an ASN list', () => {
    const rule = firewall.createRule(
      `
            (ip.geoip.asnum in $office_asns)
        `,
      lists,
    );

    expect(
      rule.match(
        new Request('http://example.org', {
          cf: { 'ip.geoip.asnum': 1234 },
        }),
      ),
    ).toBeFalsy();
  });

  it('an ASN is in an ASN list', () => {
    const rule = firewall.createRule(
      `
            (ip.geoip.asnum in $office_asns)
        `,
      lists,
    );

    expect(
      rule.match(
        new Request('http://example.org', {
          cf: { 'ip.geoip.asnum': 2345 },
        }),
      ),
    ).toBeTruthy();
  });

  it('a host is not in the list of production hosts', () => {
    const rule = firewall.createRule(
      `
            (http.host in $production_hosts)
        `,
      lists,
    );

    expect(rule.match(new Request('http://example.org'))).toBeFalsy();
  });
});
