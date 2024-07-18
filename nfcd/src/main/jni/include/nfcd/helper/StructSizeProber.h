#ifndef NFCD_STRUCTSIZEPROBER_H
#define NFCD_STRUCTSIZEPROBER_H

#include <nfcd/error.h>

#include <functional>
#include <unordered_map>
#include <vector>

class StructSizeProber {
    using pattern_t = uint16_t;

    constexpr static pattern_t PATTERNS[] = {
            0xDEAD,
            0xBEEF,
            0x1337,
    };
    constexpr static int NUM_PATTERNS = sizeof(PATTERNS) / sizeof(pattern_t);

public:
    using GetElements_t = std::function<bool(int, uint8_t*, size_t)>;

    explicit StructSizeProber(GetElements_t getElements) : mGetElements(std::move(getElements)) { }

    size_t detectStructSize(size_t estMaxElementSize) {
        LOG_ASSERT_S(estMaxElementSize % 2 == 0, return 0, "Odd estimated element size");
        size_t results[NUM_PATTERNS];

        // detect last defined byte of the struct backwards (there may be undefined bytes left)
        LOGD("[StructSizeProber] Detecting defined struct size with %zu", estMaxElementSize);
        mChunk.resize(estMaxElementSize);
        for (size_t i = 0; i < NUM_PATTERNS; i++)
            results[i] = detectWithPatternBackward(PATTERNS[i]);

        size_t definedSize = agreeResults(results);
        LOG_ASSERT_S(definedSize != 0, return 0, "Could not detect defined size");

        // detect struct size starting from last defined byte
        LOGD("[StructSizeProber] Detecting final struct size");
        mChunk.resize(estMaxElementSize * 2);
        for (size_t i = 0; i < NUM_PATTERNS; i++)
            results[i] = detectWithPatternForward(PATTERNS[i], definedSize);

        size_t structSize = agreeResults(results);
        LOG_ASSERT_S(definedSize != 0, return 0, "Could not detect struct size");
        return structSize;
    }

protected:
    size_t detectWithPatternBackward(pattern_t pattern) {
        // prepare chunk with pattern
        buildMarkedChunk(pattern);
        // read 1 element into chunk
        LOG_ASSERT_S(mGetElements(1, mChunk.data(), mChunk.size()), return 0, "Failed to read 1 element");
        // detect backwards
        return probeMarkedChunk(0, pattern, true);
    }

    size_t detectWithPatternForward(pattern_t pattern, size_t definedSize) {
        // prepare chunk with pattern
        buildMarkedChunk(pattern);
        // read 2 elements into chunk
        LOG_ASSERT_S(mGetElements(2, mChunk.data(), mChunk.size()), return 0, "Failed to read 2 elements");
        // detect forwards, starting with last defined byte
        return probeMarkedChunk(definedSize + 1, pattern, false);
    }

    void buildMarkedChunk(pattern_t pattern) {
        for (size_t i = 0; i < mChunk.size(); i += sizeof(pattern_t))
            *reinterpret_cast<pattern_t*>(mChunk.data() + i) = pattern;
    }

    size_t probeMarkedChunk(size_t offset, pattern_t pattern, bool backwards) const {
        uint8_t *pe = reinterpret_cast<uint8_t*>(&pattern);

        for (size_t i = offset; i < mChunk.size(); i++) {
            size_t j = backwards ? mChunk.size() - i - 1 : i;

            uint8_t actual = *reinterpret_cast<const uint8_t*>(mChunk.data() + j);
            uint8_t expected = pe[j % sizeof(pattern_t)];

            if (actual != expected)
                return j;
        }

        return 0;
    }

    size_t agreeResults(size_t results[NUM_PATTERNS]) {
        std::unordered_map<size_t, size_t> frequencyCount;

        // increase count for each result
        for (size_t i = 0; i < NUM_PATTERNS; i++) {
            size_t result = results[i];

            LOGD("[StructSizeProber] Got result: %zu", result);
            frequencyCount[result]++;
        }

        auto it = std::max_element(frequencyCount.begin(), frequencyCount.end());
        LOG_ASSERT_S(it->second > NUM_PATTERNS / 2, return 0, "No conclusive agreement could be reached");

        LOGD("[StructSizeProber] Agreed to result %zu with votes: %zu", it->first, it->second);
        return it->first;
    }

    GetElements_t mGetElements;
    std::vector<uint8_t> mChunk;
};

#endif //NFCD_STRUCTSIZEPROBER_H
