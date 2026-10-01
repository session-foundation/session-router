/* MinGW stubs for optional ZSTD_TRACE hooks (see contrib patch). */
#ifdef __cplusplus
extern "C" {
#endif
unsigned long long ZSTD_trace_compress_begin(void const *cctx)
{
  (void)cctx;
  return 0;
}
void ZSTD_trace_compress_end(unsigned long long ctx, void const *trace)
{
  (void)ctx;
  (void)trace;
}
unsigned long long ZSTD_trace_decompress_begin(void const *dctx)
{
  (void)dctx;
  return 0;
}
void ZSTD_trace_decompress_end(unsigned long long ctx, void const *trace)
{
  (void)ctx;
  (void)trace;
}
#ifdef __cplusplus
}
#endif
