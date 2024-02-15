#pragma once

#include <algorithm>
#include <cassert>
#include <type_traits>
#include <vector>

namespace session {

/// Selects a random sample of up to `n` elements from [`it`, `end`) that satisfy `pred(elem)`.
/// Elements are written to the output iterator `out`.  Returns the number of written elements,
/// which will be less than `n` if and only if there are fewer than `n` acceptable elements.
/// Predicate must be callable as `pred(*it)`.  Unlike std::sample, elements are always ordered
/// randomly.
template <typename InputIt, typename OutputIt, typename Predicate, typename URNG>
size_t random_conditional_sample(
        InputIt it, const InputIt end, OutputIt out, const size_t n, Predicate pred, URNG&& rng) {
    using T = std::remove_reference_t<decltype(*it)>;
    std::vector<T*> selection;
    selection.reserve(n);
    // Build up the first n acceptable elemenets from the range
    for (; selection.size() < n && it != end; ++it) {
        auto& elem = *it;
        if (pred(elem))
            selection.push_back(&elem);
    }

    for (size_t i = selection.size(); it != end; ++i, ++it) {
        assert(selection.size() == n);
        auto& elem = *it;
        if (!pred(elem))
            continue;

        // Select a random hypothetical index from 0 to i-1, where i is the number of elements we've
        // considered for admission so far.  If this gives us an index < n then replace the element
        // currently at that index with this one.
        if (size_t j = std::uniform_int_distribution<size_t>{0, i - 1}(rng); j < n)
            selection[j] = &elem;
    }

    // Shuffle; although the second loop above uses a shuffling placement, if any of the first n
    // from the first loop survived they won't be shuffled.  (We could shuffle just them, but since
    // we'll have to shuffle n elements either way, we might as well shuffle here after doing the
    // full sampling iteration).
    std::shuffle(selection.begin(), selection.end(), rng);

    for (auto* elem : selection)
        *out++ = *elem;

    return selection.size();
}

}  // namespace session
