#include <nfcd/helper/EEManager.h>
#include <nfcd/nfcd.h>

#include <cinttypes>
#include <vector>

std::set<uint16_t> EEManager::findActiveEEs() const {
    std::set<uint16_t> result;

    // exact number of EEs in the list
    size_t eeCount = countEEs();
    // approximate or exact struct size as needed
    size_t structSize = findStructSize(eeCount);

    if (eeCount > 0) {
        std::vector<uint8_t> buffer(structSize * eeCount);

        uint8_t num_ee = eeCount;
        auto rv = globals.hNFA_EeGetInfo->call<def_NFA_EeGetInfo>(
                &num_ee, reinterpret_cast<void*>(buffer.data()));
        LOG_ASSERT_S(rv == NCI_STATUS_OK, return result, "[EEManager] NFA_EeGetInfo failed for get data");

        for (size_t i = 0; i < num_ee; i++) {
            uint8_t *eeInfo = buffer.data() + structSize * i;

            // uint16_t ee_handle is always at the start of each struct
            uint16_t ee_handle = *reinterpret_cast<uint16_t *>(eeInfo);
            // uint8_t ee_status is always at offset 2 in each struct
            uint8_t ee_status = *reinterpret_cast<uint16_t *>(eeInfo + sizeof(uint16_t));

            // only non-deactivated EEs
            if (ee_status != NFA_EE_STATUS_INACTIVE)
                result.insert(ee_handle);
        }
    }

    return result;
}

void EEManager::markDeactivated(uint16_t handle) {
    mDeactivated.insert(handle);
}

void EEManager::markActivated(uint16_t handle) {
    mDeactivated.erase(handle);
}

size_t EEManager::countEEs() const {
    std::vector<uint8_t> temp(255 * getApproxStructSize());

    uint8_t num_ee = 255;
    auto rv = globals.hNFA_EeGetInfo->call<def_NFA_EeGetInfo>(
            &num_ee, reinterpret_cast<void*>(temp.data()));
    LOG_ASSERT_S(rv == NCI_STATUS_OK, return 0, "[EEManager] NFA_EeGetInfo failed for count");

    LOGD("[EEManager] Got count: %d", (int)num_ee);
    return num_ee;
}

size_t EEManager::findStructSize(size_t eeCount) const {
    StructSizeProber prober([] (int numEE, uint8_t *dest, size_t size) {
        uint8_t num_ee = numEE;

        auto rv = globals.hNFA_EeGetInfo->call<def_NFA_EeGetInfo>(&num_ee, dest);
        LOG_ASSERT_S(rv == NCI_STATUS_OK, return false, "[EEManager] NFA_EeGetInfo failed for prober");

        return num_ee == numEE;
    });

    // no or one EEs, no exact struct size needed
    if (eeCount <= 1)
        return getApproxStructSize();

    // probe and cache struct size if needed
    if (!mStructSize)
        mStructSize = prober.detectStructSize(getApproxStructSize());

    // return exact struct size for EE count > 1
    return mStructSize;
}
