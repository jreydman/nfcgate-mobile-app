#ifndef NFCGATE_EEMANAGER_H
#define NFCGATE_EEMANAGER_H

#include <cinttypes>
#include <set>

class EEManager {
    // 10KB to be sure
    static constexpr size_t estMaxElementSize = 10000;
public:
    /// find all currently active EEs
    std::set<uint16_t> findActiveEEs() const;
    /// get all manually deactivated and not yet re-activated EEs
    std::set<uint16_t> deactivatedEEs() const {
        return mDeactivated;
    }

    /// mark the specified EE as explicitly deactivated
    void markDeactivated(uint16_t handle);
    /// mark the specified EE as explicitly activated
    void markActivated(uint16_t handle);

protected:
    // get the number of EEs on this system
    size_t countEEs() const;

    // measure the size of the EE struct using struct size probing
    size_t findStructSize(size_t eeCount) const;

    // get an approximation of the struct size
    size_t getApproxStructSize() const {
        return mStructSize ? mStructSize : estMaxElementSize;
    }

    mutable size_t mStructSize = 0;
    std::set<uint16_t> mDeactivated;
};

#endif //NFCGATE_EEMANAGER_H
