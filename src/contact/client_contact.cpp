#include "client_contact.hpp"

#include "constants/path.hpp"
#include "crypto/crypto.hpp"
#include "util/bspan.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"
#include "util/underlying.hpp"

#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

#include <algorithm>
#include <type_traits>

namespace srouter
{
    static auto logcat = log::Cat("client-intro");

    ClientContact::ClientContact(
        PubKey pk,
        std::vector<dns::SRVData> srvs,
        protocol_flag protocols,
        sys_ms signed_at,
        std::optional<net::ExitPolicy> policy)
        : _pubkey{std::move(pk)},
          _srv{std::move(srvs)},
          _protos{protocols},
          _signed_at{signed_at},
          _exit_policy{std::move(policy)}
    {}

    ClientContact::ClientContact(std::span<const std::byte> buf, sys_ms signed_at) : _signed_at{signed_at}
    {
        oxenc::bt_dict_consumer btdc{buf};

        auto version = btdc.require<uint8_t>("");

        if (version != VERSION)
            throw std::runtime_error{
                "Deserialized ClientContact with unsupported version {} (expected {})!"_format(version, VERSION)};

        _pubkey.assign(btdc.require_span<std::byte, PubKey::SIZE>("a"));

        if (btdc.skip_until("e"))
            _exit_policy.emplace().bt_decode(btdc.consume_dict_consumer());

        for (auto sublist = btdc.require<oxenc::bt_list_consumer>("i"); not sublist.is_finished();)
            _intros.emplace_back(sublist.consume_dict_consumer());

        if (!std::ranges::is_sorted(_intros, std::ranges::greater{}, &ClientIntro::expiry))
            throw std::runtime_error{"Invalid ClientContact: intros expiries are non-descending"};

        _protos = static_cast<protocol_flag>(btdc.require<std::underlying_type_t<protocol_flag>>("p"));

        if (auto sublist = btdc.maybe<oxenc::bt_list_consumer>("s"))
            while (not sublist->is_finished())
                _srv.emplace_back(sublist->consume_dict_consumer());

        btdc.finish();
    }

    void ClientContact::update_intros(std::vector<ClientIntro> iset)
    {
        if (iset.empty())
            throw std::invalid_argument{"Cannot update ClientContact with no ClientIntros!"};
        _intros = std::move(iset);
        std::ranges::stable_sort(_intros, std::ranges::greater{}, &ClientIntro::expiry);
        log::debug(logcat, "ClientContact updated with {} ClientIntros", _intros.size());
    }

    std::vector<std::byte> ClientContact::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;
        btdp.append<uint8_t>("", VERSION);

        btdp.append("a", _pubkey.to_view());

        if (_exit_policy)
            _exit_policy->bt_encode(btdp.append_dict("e"));

        {
            auto sublist = btdp.append_list("i");
            for (auto& i : _intros)
                i.bt_encode(sublist.append_dict());
        }

        btdp.append("p", to_underlying(_protos));

        if (not _srv.empty())
        {
            auto sublist = btdp.append_list("s");
            for (auto& s : _srv)
                s.bt_encode(sublist.append_dict());
        }

        auto encoded = btdp.view();
        std::vector<std::byte> ret;
        ret.resize(encoded.size());
        std::memcpy(ret.data(), encoded.data(), encoded.size());
        return ret;
    }

    std::chrono::sys_seconds ClientContact::expiry() const
    {
        if (_intros.empty())
            return {};
        return _intros.front().expiry;
    }

    bool ClientContact::is_expired(sys_ms now) const
    {
        // We only need to check the first one, because this is sorted newest-to-oldest and so if
        // the first is expired they all are.
        return _intros.empty() || _intros.front().is_expired(now);
    }

    std::string ClientContact::encrypt_and_sign(const Ed25519BlindedKey& blinded)
    {
        auto nonce = SymmNonce::make_random();
        auto encrypted = bt_encode();
        crypto::xchacha20(encrypted, SymmKey{_pubkey}, nonce);
        _signed_at = srouter::time_now_ms();

        /** Encrypted client contact values:
                "i" blinded pubkey
                "n" nonce
                "t" signing time
                "x" encrypted payload
                "~" signature (verifiable with "i")
        */
        oxenc::bt_dict_producer btdp;
        btdp.append("i", blinded.pubkey.to_view());
        btdp.append("n", nonce.to_view());
        btdp.append("t", _signed_at.time_since_epoch().count());
        btdp.append("x", std::span{encrypted});
        btdp.append_signature("~", [&blinded](std::span<const std::byte> m) { return blinded.sign(m); });

        return std::move(btdp).str();
    }

    ClientContact ClientContact::decrypt(std::span<const std::byte> enccc, const PubKey& root)
    {
        try
        {
            PubKey blinded;
            oxenc::bt_dict_consumer btdc{enccc};
            blinded.assign(btdc.require_span<std::byte, PubKey::SIZE>("i"));
            SymmNonce nonce;
            nonce.assign(btdc.require_span<std::byte, SymmNonce::SIZE>("n"));
            auto signed_at = sys_ms{std::chrono::milliseconds{btdc.require<int64_t>("t")}};
            auto enc = btdc.require_span<std::byte>("x");

            btdc.require_signature("~", [&blinded](std::span<const std::byte> m, std::span<const std::byte> s) {
                if (s.size() != Signature::SIZE)
                    throw std::runtime_error{"Invalid signature: not 64 bytes"};

                if (not blinded.verify(m, SignatureView{s.first<Signature::SIZE>()}))
                    throw std::runtime_error{"Encrypted client contact signature verification failed"};
            });

            std::vector<std::byte> decrypted{enc.begin(), enc.end()};
            crypto::xchacha20(decrypted, SymmKey{root}, nonce);

            return ClientContact{decrypted, signed_at};
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "ClientContact decryption/deserialization failed: {}", e.what());
            log::trace(logcat, "Failing Encrypted CC data: {}", buffer_printer{enccc});
            throw;
        }
    }

    std::string ClientContact::to_string() const
    {
        return "CC[{}{}, {}, {} intros]"_format(
            _pubkey.short_string(), _exit_policy ? ", exit" : "", _intros.size(), srouter::to_string(_protos));
    }

}  //  namespace srouter
