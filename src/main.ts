import {
    initWirefilter,
    wirefilter_externally_allocated_str_t,
    WIREFILTER_TYPE_BOOL,
    WIREFILTER_TYPE_INT,
} from "./wirefilter";
import {Firewall} from "./firewall";
import {Request} from "node-fetch";

console.log("hello")

const wirefilter = initWirefilter('libs/libwirefilter_ffi.dylib')

console.log(wirefilter.wirefilter_get_version().data)

function wirefilter_string(s: string) {
    let str = new wirefilter_externally_allocated_str_t();
    str.data = s;
    str.length = s.length;
    return str;
}

const scheme = wirefilter.wirefilter_create_scheme();
console.log(wirefilter.wirefilter_add_type_field_to_scheme(
    scheme,
    wirefilter_string("tcp.port"),
    WIREFILTER_TYPE_INT
));
console.log(wirefilter.wirefilter_add_type_field_to_scheme(
    scheme,
    wirefilter_string("ssl"),
    WIREFILTER_TYPE_BOOL
))

const parsintResult = wirefilter.wirefilter_parse_filter(
    scheme,
    wirefilter_string("tcp.port == 80")
);
console.log(parsintResult.ok.success)
if (parsintResult.ok.success != 1) {
    throw Error(`err: ${parsintResult.err.msg.data}`)
}

const ast = parsintResult.ok.ast;

const compiling_result = wirefilter.wirefilter_compile_filter(ast);
console.log(compiling_result.ok.success);
const filter = compiling_result.ok.filter;

const exec_ctx = wirefilter.wirefilter_create_execution_context(scheme);

console.log(wirefilter.wirefilter_add_int_value_to_execution_context(
    exec_ctx,
    wirefilter_string("tcp.port"),
    80
));
wirefilter.wirefilter_add_bool_value_to_execution_context(
    exec_ctx,
    wirefilter_string("ssl"),
    true
);

const matchingResult = wirefilter.wirefilter_match(filter, exec_ctx)

console.log(`Matched: ${matchingResult.ok.success}`)
console.log(`Matched: ${matchingResult.ok.value}`)

wirefilter.wirefilter_free_execution_context(exec_ctx)
wirefilter.wirefilter_free_compiled_filter(filter);
wirefilter.wirefilter_free_scheme(scheme);

const firewall = new Firewall()
const rule = firewall.createFirewallRule('http.request.method eq "GET"');

console.log(rule.match(new Request('http://google.com')))
console.log(rule.match(new Request('http://google.com', {
    method: 'POST'
})))
