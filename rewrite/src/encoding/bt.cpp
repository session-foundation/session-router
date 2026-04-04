#include "bt.hpp"

#include <sodium.h>

#include <stdexcept>

namespace sr::encoding
{

    std::string get_signable_prefix(const std::string& bt_dict)
    {
        // A BT dict starts with 'd' and ends with 'e'.
        // We need everything from 'd' up to (but not including) the "~" key-value.
        // The "~" key is encoded as "1:~" in bencode.
        //
        // Strategy: find the last occurrence of "1:~" which is the signature key.
        // The prefix is everything before that occurrence.

        if (bt_dict.empty() || bt_dict[0] != 'd')
            throw std::runtime_error("get_signable_prefix: not a BT dict");

        // Find "1:~" — the BT encoding of the key "~"
        auto pos = bt_dict.rfind("1:~");
        if (pos == std::string::npos || pos == 0)
            throw std::runtime_error("get_signable_prefix: no signature key found");

        return bt_dict.substr(0, pos);
    }

    std::string append_signature(
        const std::string& bt_prefix,
        const unsigned char* secret_key)
    {
        // bt_prefix is a partial BT dict (starts with 'd', no closing 'e').
        // We sign the prefix bytes, then append "~":signature and close with 'e'.

        unsigned char sig[crypto_sign_BYTES];
        crypto_sign_detached(
            sig,
            nullptr,
            reinterpret_cast<const unsigned char*>(bt_prefix.data()),
            bt_prefix.size(),
            secret_key);

        // Build: prefix + "1:~" + "64:" + sig_bytes + "e"
        std::string result;
        result.reserve(bt_prefix.size() + 3 + 3 + 64 + 1);
        result.append(bt_prefix);
        result.append("1:~");
        result.append("64:");
        result.append(reinterpret_cast<const char*>(sig), 64);
        result.append("e");

        return result;
    }

    bool verify_signature(
        const std::string& bt_dict,
        const unsigned char* pubkey)
    {
        try
        {
            auto prefix = get_signable_prefix(bt_dict);

            // Extract signature: parse the "~" value from the dict
            bt_dict_consumer dc{bt_dict};
            if (!dc.skip_until("~"))
                return false;

            auto sig_sv = dc.consume_string_view();
            if (sig_sv.size() != crypto_sign_BYTES)
                return false;

            return crypto_sign_verify_detached(
                       reinterpret_cast<const unsigned char*>(sig_sv.data()),
                       reinterpret_cast<const unsigned char*>(prefix.data()),
                       prefix.size(),
                       pubkey)
                == 0;
        }
        catch (...)
        {
            return false;
        }
    }

}  // namespace sr::encoding
