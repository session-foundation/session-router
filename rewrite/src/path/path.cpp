#include <sodium.h>
#include <sr/path/path.hpp>

#include <cstring>
#include <random>

namespace sr::path
{

    using namespace sr::crypto;

    Path::Path(std::vector<Hop> hops, std::chrono::steady_clock::time_point created)
        : _hops{std::move(hops)}, _created{created}
    {
        // Random lifetime fuzz
        std::random_device rd;
        std::mt19937 rng{rd()};
        std::uniform_int_distribution<int> dist(0, MAX_FUZZ.count());
        _lifetime_fuzz = std::chrono::seconds(dist(rng) * 60);
    }

    std::vector<std::byte> Path::encrypt_data(std::span<const std::byte> plaintext, const Nonce& nonce) const
    {
        // Start with plaintext copy
        std::vector<std::byte> buf(plaintext.begin(), plaintext.end());

        // Apply onion layers in REVERSE order (pivot first, edge last).
        // The relay peels in FORWARD order (edge first), so the nonce
        // must be computed to match forward peeling:
        //   relay 0 decrypts with nonce, XOR with hop[0].xor_nonce
        //   relay 1 decrypts with nonce', XOR with hop[1].xor_nonce
        //   relay N decrypts with nonce''
        // For encryption (reverse), we pre-compute each hop's nonce:
        std::vector<Nonce> hop_nonces(_hops.size());
        hop_nonces[0] = nonce;
        for (size_t i = 1; i < _hops.size(); ++i)
        {
            hop_nonces[i] = hop_nonces[i - 1];
            for (size_t j = 0; j < hop_nonces[i].size(); ++j)
                hop_nonces[i][j] ^= _hops[i - 1].xor_nonce[j];
        }

        // Encrypt in reverse: pivot layer first, edge layer last
        for (int i = static_cast<int>(_hops.size()) - 1; i >= 0; --i)
        {
            xchacha20_inplace(buf, reinterpret_cast<const SymmetricKey&>(_hops[i].shared_secret), hop_nonces[i]);
        }

        return buf;
    }

    std::optional<std::vector<std::byte>> Path::decrypt_data(std::span<std::byte> data, Nonce& nonce) const
    {
        // Peel onion layers in FORWARD order (edge first, pivot last).
        for (size_t i = 0; i < _hops.size(); ++i)
        {
            xchacha20_inplace(data, reinterpret_cast<const SymmetricKey&>(_hops[i].shared_secret), nonce);

            // XOR nonce for next layer
            if (i + 1 < _hops.size())
            {
                for (size_t j = 0; j < nonce.size(); ++j)
                    nonce[j] ^= _hops[i].xor_nonce[j];
            }
        }

        return std::vector<std::byte>(data.begin(), data.end());
    }

    bool Path::is_expired(std::chrono::steady_clock::time_point now) const
    {
        return (now - _created) > (MAX_LIFETIME + _lifetime_fuzz);
    }

}  // namespace sr::path
