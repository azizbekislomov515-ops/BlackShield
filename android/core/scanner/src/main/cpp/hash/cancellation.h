#pragma once

#include <atomic>

namespace blackshield::hash {

/** Cooperative cancellation flag. Set from any thread; polled by HashEngine between chunks. */
class CancellationFlag {
public:
    void Cancel() noexcept { cancelled_.store(true, std::memory_order_release); }

    bool IsCancelled() const noexcept { return cancelled_.load(std::memory_order_acquire); }

private:
    std::atomic<bool> cancelled_{false};
};

}  // namespace blackshield::hash
