"""Run one four-byte CUDA computation per visible GPU without PyTorch dependencies."""
import ctypes as C
import json

PTX = b""".version 6.0
.target sm_50
.address_size 64
.visible .entry increment(.param .u64 output, .param .u32 input) {
  .reg .b64 %rd;
  .reg .b32 %r;
  ld.param.u64 %rd, [output];
  ld.param.u32 %r, [input];
  add.u32 %r, %r, 1;
  st.global.u32 [%rd], %r;
  ret;
}
"""


def main():
    driver = C.CDLL("libcuda.so.1")
    def check(name, *args):
        status = getattr(driver, name)(*args)
        if status:
            error = C.c_char_p()
            driver.cuGetErrorString(status, C.byref(error))
            raise RuntimeError(f"{name}: {status} {error.value!r}")
    check("cuInit", 0)
    count = C.c_int()
    check("cuDeviceGetCount", C.byref(count))
    results = []
    for index in range(count.value):
        device = C.c_int()
        context = C.c_void_p()
        module = C.c_void_p()
        pointer = C.c_uint64()
        try:
            check("cuDeviceGet", C.byref(device), index)
            check("cuCtxCreate_v2", C.byref(context), 0, device)
            check("cuModuleLoadData", C.byref(module), C.c_char_p(PTX))
            kernel = C.c_void_p()
            check("cuModuleGetFunction", C.byref(kernel), module, b"increment")
            check("cuMemAlloc_v2", C.byref(pointer), C.c_size_t(4))
            value = C.c_uint32(41)
            parameters = (C.c_void_p * 2)(
                C.cast(C.byref(pointer), C.c_void_p),
                C.cast(C.byref(value), C.c_void_p),
            )
            check("cuLaunchKernel", kernel, 1, 1, 1, 1, 1, 1, 0,
                  C.c_void_p(), parameters, C.c_void_p())
            check("cuCtxSynchronize")
            result = C.c_uint32()
            check("cuMemcpyDtoH_v2", C.byref(result), pointer, C.c_size_t(4))
            if result.value != 42:
                raise RuntimeError(f"GPU {index}: expected 42, got {result.value}")
            results.append({"gpu": index, "result": result.value, "passed": True})
        except RuntimeError as error:
            results.append({"gpu": index, "passed": False, "error": str(error)})
        finally:
            if pointer.value:
                check("cuMemFree_v2", pointer)
            if module.value:
                check("cuModuleUnload", module)
            if context.value:
                check("cuCtxDestroy_v2", context)
    if not results:
        raise RuntimeError("No visible CUDA GPUs")
    passed = all(result["passed"] for result in results)
    print(json.dumps({"passed": passed, "gpu_count": count.value, "results": results}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
