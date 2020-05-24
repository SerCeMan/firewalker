![]()

# Firewalker
[![Build Status](https://travis-ci.org/SerCeMan/firewalker.svg?branch=master)](https://travis-ci.org/SerCeMan/firewalker)
[![Codecov](https://codecov.io/gh/SerCeMan/firewalker/branch/master/graph/badge.svg)](https://codecov.io/gh/SerCeMan/firewalker)
[![npm version](https://badge.fury.io/js/firewalker.svg)](https://www.npmjs.com/package/firewalker)


A framework for executing and testing Cloudflare WAF rules locally.

```typescript
const firewall = new Firewall()
const rule = firewall.createRule(`
    http.host eq "www.example.org"
`)

rule.match(new Request('http://www.example.org')) // -> true
rule.match(new Request('http://www.example.com')) // -> false
```

## Motivation

It's easy to treat firewall rules as plain configuration. However, over time the number of rules and their complexity grows. It's incredibly easy to manage a couple of rules that look like.
```
http.host eq "www.example.org" 
```

And end up with a rule that looks more like. 
```wireshark
http.host matches "(www|api)\.example\.org"
and not lower(http.request.uri.path) matches "/(auth|login|logut).*"
and (
  any(http.request.uri.args.names[*] == "token") or
  ip.src in { 93.184.216.34 62.122.170.171 }
)
or cf.threat_score lt 10
``` 

Manually testing the rule like the above is error-prone as humans are known to make mistakes. After a few steps up in complexity, it becomes apparent that firewall rules are code, and need to be treated as code. They need to be stored in a source code repository, managed with a tool like Terraform, and the changes need to be tested on CI. Here is where Firewalker comes into play allowing you to write unit tests to ensure that a change to the path regex isn't going to block all of the traffic to your site or cancel out the effect of the rule completely.

For instance, for the rule above, you can define multiple assertions using Firewalker.

```typescript
const rule = firewall.createRule(/* */)

expect(rule.match(new Request('http://www.example.org'))).toBeFalsy()
expect(rule.match(new Request('http://www.example.org?token=abc'))).toBeTruthy()
expect(rule.match(new Request('http://www.example.org/login/user?token=abc'))).toBeFalsy()
expect(rule.match(new Request('http://www.example.org/login/user?token=abc', {
    cf: {'cf.threat_score': 5}
}))).toBeTruthy();
// etc
```


## Supported platforms
Firewalker relies on a binary build [wirefilter](https://github.com/cloudflare/wirefilter) to run and execute the firewall rules. Therefore, only the platforms which binaries were pre-built will be able to run Firewalker. Currently supported platforms are:

* MacOS
* Linux

## Disclaimer
The Firewalker project is not officially supported by Cloudflare or affiliated with Cloudflare in any way. While Firewalker tries to preserve the semantics of the Cloudflare WAF rule engine, there will always be some differences, so use it at your own risk as general guidance for local testing rather than the ultimate truth.

## Contribute
Contributions are always welcome!
