extern "C" {
#include <xhook.h>
#include <xh_core.h>
}

#include <nfcd/hook/impl/XHook.h>

XHook::XHook(const std::string &name, void *hookFn, void *libraryHandle, const std::string &reLibrary) :
        IHook(name, hookFn, libraryHandle),
        mReLibrary(reLibrary) {
    XHook::hookInternal();
}

void XHook::hookInternal() {
    int r = xhook_register(mReLibrary.c_str(), mName.c_str(), mHookFn, &mAddress);
    LOG_ASSERT_S(r == 0, return, "XHook failed: %d", r);

    mHooked = true;
}
