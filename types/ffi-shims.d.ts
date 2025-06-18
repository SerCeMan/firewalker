// types/ffi-shims.d.ts
declare module 'ffi-napi' {
    const ffi: any;
    export default ffi;
}

declare module 'ref-napi' {
    const ref: any;
    export default ref;
}

declare module 'ref-array-di' {
    const ref_array_di: any;
    export default ref_array_di;
}

declare module 'ref-struct-di' {
    const ref_struct_di: any;
    export default ref_struct_di;
}

declare module 'ref-union-di' {
    const ref_union_di: any;
    export default ref_union_di;
}
