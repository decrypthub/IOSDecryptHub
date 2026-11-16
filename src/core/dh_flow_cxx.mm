// Controlled C++ unwind fixture; never runs in the QBDI live VM.
extern "C" void DHFlowThrowCXX(void) {throw 73;}
extern "C" int DHFlowCatchCXX(void (*body)(void *),void *context) {
    try {body(context);} catch(int value) {return value;}return 0;
}
