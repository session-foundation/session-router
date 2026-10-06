#include "message.hpp"

#include "encode.hpp"
#include "flags.hpp"
#include "srv_data.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

#include <oxenc/endian.h>
#include <sodium/crypto_shorthash_siphash24.h>

#include <array>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

    Message::Message(Question question) : hdr_id{0}, hdr_fields{}, question{std::move(question)} {}

    Message Message::clone() const
    {
        Message c;
        c.hdr_id = hdr_id;
        c.hdr_fields = hdr_fields;
        c.question = question;
        c.additional_edns = additional_edns;
        // Don't copy answers, or rr_name_override (which is just an intermediate answers helper)
        return c;
    }

    std::vector<std::byte> Message::encode(bool max_size) const
    {
        std::vector<std::byte> tmp;
        tmp.resize(
            max_size              ? std::numeric_limits<uint16_t>::max()
                : additional_edns ? additional_edns->max_payload()
                                  : 512);

        prev_names_t prev_names;
        std::span<std::byte> buf{tmp};
        uint16_t buf_offset = 0;

        // A Message is only ever encoded as a response (upstream forwarding goes through unbound
        // and RawMessage), so QR always belongs here regardless of what the individual reply path
        // set up.  AD, on the other hand, has to be cleared: we copy the header fields from the
        // request, but we do no DNSSEC validation and so must not claim the data is authenticated.
        uint16_t fields = (hdr_fields | flags_QR) & ~flags_AD;

        buf_offset += write_ints_into(
            buf,
            hdr_id,
            fields,
            question ? uint16_t{1} : uint16_t{0},
            static_cast<uint16_t>(answers.size()),
            static_cast<uint16_t>(authorities.size()),
            static_cast<uint16_t>(additional_edns ? 1 : 0 /*additional.size()*/));

        if (question)
            question->encode(buf, prev_names, buf_offset);

        // If we run out of space and have to truncate then we are still supposed to include the
        // EDNS part of the additional response, but other answers don't have to be: so if we hit
        // such a failure, we're back up to this point (throwing away all the answers) so that we
        // can include the EDNS response info.
        auto initial_len = buf_offset;

        try
        {
            for (auto& a : answers)
                a->encode(buf, prev_names, buf_offset);

            for (auto& a : authorities)
                a->encode(buf, prev_names, buf_offset);

            if (additional_edns)
                additional_edns->encode(buf, prev_names, buf_offset);
        }
        catch (const std::out_of_range&)
        {
            log::debug(logcat, "Response too large!  Setting truncation bit");

            oxenc::write_host_as_big(fields | flags_TC, tmp.data() + 2);

            // Reset our buffer position back to just after the questions were added.  We do this
            // even if we aren't going to add EDNS stuff below, because we are not supposed to
            // include partial RR entries in a truncated reply.
            buf = std::span{tmp.data() + initial_len, tmp.size() - initial_len};
            // Replace the answers count with a 0:
            oxenc::write_host_as_big(0, tmp.data() + 2 + 2 + 2);
            buf_offset = initial_len;

            if (additional_edns)
            {
                try
                {
                    additional_edns->encode(buf, prev_names, buf_offset);
                }
                catch (const std::out_of_range&)
                {
                    // If this failed to then we don't have enough space for the EDNS so we'll just have to omit it
                    log::debug(logcat, "Unable to fit EDNS additional into DNS response!");
                    buf = std::span{tmp.data() + initial_len, tmp.size() - initial_len};
                    buf_offset = initial_len;
                    // Replace the additional count with a 0:
                    oxenc::write_host_as_big(0, tmp.data() + 2 + 2 + 2 + 2 + 2);
                }
            }
        }

        // Trim the excess:
        tmp.resize(tmp.size() - buf.size());
        tmp.shrink_to_fit();

        return tmp;
    }

    static std::array<std::byte, 24> make_server_cookie(
        std::span<const std::byte, 8> client_cookie,
        std::span<const std::byte> client_ip,
        std::span<const std::byte, 16> server_cookie_secret,
        std::chrono::sys_seconds ts = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()))
    {
        assert(client_ip.size() == 4 || client_ip.size() == 16);

        static_assert(server_cookie_secret.size() == crypto_shorthash_siphash24_KEYBYTES);

        std::array<std::byte, 24> cookie;
        auto ccookie = std::span{cookie}.first<8>();
        auto scookie = std::span{cookie}.last<16>();
        std::memcpy(ccookie.data(), client_cookie.data(), 8);

        // The first 8 bytes of the server cookie (as per RFC 9018) are:
        // - version (always 1)
        // - three reserved bytes
        // - 4-byte, uint32 unix timestamp
        scookie[0] = std::byte{1};  // Version
        scookie[1] = std::byte{0};  // -
        scookie[2] = std::byte{0};  // - reserved
        scookie[3] = std::byte{0};  // -
        auto ts_val = static_cast<uint32_t>(ts.time_since_epoch().count());
        oxenc::write_host_as_big(ts_val, &scookie[4]);

        // The last 8 bytes of the server cookie are a hash of 8-byte client
        // cookie, then the above 8 bytes server cookie fields, then the
        // 4- or 16-byte client IP (in network order notation).
        std::array<unsigned char, 32> hash_data{{0}};
        std::memcpy(hash_data.data(), ccookie.data(), 8);
        std::memcpy(hash_data.data() + 8, scookie.data(), 8);
        std::memcpy(hash_data.data() + 16, client_ip.data(), client_ip.size());
        crypto_shorthash_siphash24(
            reinterpret_cast<unsigned char*>(scookie.data() + 8),
            hash_data.data(),
            16 + client_ip.size(),
            reinterpret_cast<const unsigned char*>(server_cookie_secret.data()));

        return cookie;
    }

    std::optional<Message> Message::extract_question(
        std::span<const std::byte>& buf,
        std::span<const std::byte, 16> server_cookie_secret,
        std::span<const std::byte> client_ip)
    {
        if (client_ip.size() != 4 && client_ip.size() != 16)
            throw std::logic_error{"Invalid client IP for Message::extract_question"};
        auto result = std::make_optional<Message>();
        auto& m = *result;
        uint16_t qd_count, an_count, ns_count, ar_count;
        if (!extract_ints(buf, m.hdr_id, m.hdr_fields, qd_count, an_count, ns_count, ar_count))
        {
            result.reset();
            return result;
        }
        if (qd_count > 1)
        {
            log::warning(logcat, "Ignoring archaic DNS request with {} > 1 questions", qd_count);
            m.bad_extract = true;
            m.formerr();
            return result;
        }
        // Ignore these:
        // m.answers.resize(an_count);
        // m.authorities.resize(ns_count);
        // m.additional.resize(ar_count);

        try
        {
            if (qd_count)
            {
                auto& q = m.question.emplace();
                if (!q.extract(buf))
                    throw std::invalid_argument{"invalid question"};
            }

            // Skip any answers or authority records:
            for (uint16_t i = 0; i < an_count; i++)
                if (!ParsedRR::extract(buf))
                    throw std::invalid_argument{"invalid answer RR"};
            for (uint16_t i = 0; i < ns_count; i++)
                if (!ParsedRR::extract(buf))
                    throw std::invalid_argument{"invalid authority RR"};

            // In the additional section we look for an EDNS entry, and skip anything else:
            for (uint16_t i = 0; i < ar_count; i++)
            {
                static_assert(crypto_shorthash_siphash24_KEYBYTES == 16);
                auto a_rr = ParsedRR::extract(buf);
                if (!a_rr)
                    throw std::invalid_argument{"invalid additional RR"};
                if (a_rr->name != "." || a_rr->rr_type != RRType::OPT)
                {
                    continue;
                }

                if (m.additional_edns)
                    throw std::invalid_argument{"found invalid multiple additional OPT records"};

                auto max_payload = static_cast<uint16_t>(a_rr->rr_class);
                m.additional_edns.emplace(std::min<uint16_t>(max_payload, 1232), a_rr->ttl);

                std::optional<std::vector<std::byte>> cookie;
                for (auto optbuf = a_rr->rdata; !optbuf.empty();)
                {
                    if (optbuf.size() < 4)
                        throw std::invalid_argument{"additional OPT data section too small"};
                    auto opt_code = oxenc::load_big_to_host<uint16_t>(optbuf.data());
                    auto opt_len = oxenc::load_big_to_host<uint16_t>(optbuf.data() + 2);
                    optbuf = optbuf.subspan(4);
                    if (opt_len > optbuf.size())
                        throw std::invalid_argument{"additional OPT option value length too small"};
                    auto value = optbuf.subspan(0, opt_len);
                    optbuf = optbuf.subspan(opt_len);

                    if (opt_code == PRR_EDNS::OPT_COOKIE)
                    {
                        if (m.additional_edns->cookie)
                            throw std::invalid_argument{"Duplicate OPT client cookies"};

                        if (value.size() == 8)
                        {
                            // This is the client sending a new cookie, requesting a new server
                            // cookie (i.e. because it doesn't currently have one).

                            m.additional_edns->cookie =
                                make_server_cookie(value.first<8>(), client_ip, server_cookie_secret);
                        }
                        else if (value.size() == 24)
                        {
                            // This is the client sending its cookie along with a previously
                            // obtained server cookie for that client cookie, so we are supposed
                            // to validate it.
                            auto ccookie = value.first<8>();
                            auto scookie = value.last<16>();

                            std::chrono::sys_seconds ts{
                                std::chrono::seconds{oxenc::load_big_to_host<uint32_t>(&scookie[4])}};

                            auto expected = make_server_cookie(ccookie, client_ip, server_cookie_secret, ts);
                            bool bad_cookie = std::memcmp(value.data(), expected.data(), 24) != 0;

                            auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());

                            if (!bad_cookie && ts >= now - 30min && ts <= now + 5min)
                                // Cookie is good and the timestamp in it is close to now, so the
                                // cookie stays as-is.
                                std::memcpy(m.additional_edns->cookie.emplace().data(), value.data(), 24);

                            else
                            {
                                // If the cookie timestamp is too far away then it is a badcookie
                                // failure.  (We don't have to worry about client clock skew because
                                // supposedly *we* issued this with the timestamp in it).
                                if (bad_cookie || ts < now - 1h || ts > now + 5min)
                                {
                                    // When this is set we'll send a proper bad cookie response
                                    // immediately after parsing:
                                    m.additional_edns->bad_cookie = true;
                                    // Extended rcode is, um, a wee bit hacky: we put the high 8
                                    // bits of the 12-bit error code into the OPT TTL field, and
                                    // then continue to use the 4-bit RCODE for the bottom 4 bits.
                                    m.additional_edns->ttl =
                                        std::chrono::seconds{(uint32_t{PRR_EDNS::EXT_RCODE_BADCOOKIE} >> 4) << 24};
                                    // (The other bytes are all 0 values)
                                }

                                // else it's valid, just a little bit (but not too) old and they are
                                // due for a new cookie.

                                // In either of the above cases, we give the client a new cookie
                                // to use, with an updated new timestamp
                                m.additional_edns->cookie =
                                    make_server_cookie(ccookie, client_ip, server_cookie_secret, now);
                            }
                        }
                        // Else we have an unparseable/non-understood cookie, and so we are supposed
                        // to ignore the option and discard the cookie data.
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            log::debug(logcat, "failed to parse DNS message: {}", e.what());
            m.bad_extract = true;
            m.formerr();
        }

        return result;
    }

    void Message::set_rr_name(std::optional<std::string> name) { rr_name_override = std::move(name); }

    // TODO FIXME: "RA" means we advertise that we support recursion, but we should only do that
    // when we have an upstream DNS server available.  (This TODO is also in server.cpp)
    static constexpr uint16_t reply_flags = flags_QR | flags_AA | flags_RA;

    void Message::add_nodata_reply()
    {
        if (question)
            hdr_fields |= reply_flags;
    }

    template <std::derived_from<ResourceRecord> RR, typename... Args>
    void make_reply(Message& m, std::chrono::seconds ttl, Args&&... args)
    {
        if (!m.question)
            return;

        m.hdr_fields |= reply_flags;

        m.answers.push_back(std::make_unique<RR>(std::string{m.get_rr_name()}, ttl, std::forward<Args>(args)...));
    }

    void Message::add_reply(const ipv4& addr, std::chrono::seconds ttl) { make_reply<RR_A>(*this, ttl, addr); }

    void Message::add_reply(const ipv6& addr, std::chrono::seconds ttl) { make_reply<RR_AAAA>(*this, ttl, addr); }

    void Message::add_cname_reply(std::string_view name, std::chrono::seconds ttl)
    {
        make_reply<RR_CNAME>(*this, ttl, std::string{name});
    }

    void Message::add_ptr_reply(std::string_view name, std::chrono::seconds ttl)
    {
        make_reply<RR_PTR>(*this, ttl, std::string{name});
    }

    void Message::add_reply(const SRVData& srv, std::chrono::seconds ttl) { make_reply<RR_SRV>(*this, ttl, srv); }

    void Message::add_txt_reply(std::string_view txt, std::chrono::seconds ttl) { make_reply<RR_TXT>(*this, ttl, txt); }

    Message&& Message::apply_rcode(uint16_t rcode, bool authoritative)
    {
        hdr_fields = set_rcode(hdr_fields, rcode);
        if (question)
        {
            hdr_fields |= reply_flags;
            if (authoritative)
                hdr_fields |= flags_AA;
            else
                hdr_fields &= ~flags_AA;
        }
        return std::move(*this);
    }

    Message&& Message::servfail()
    {
        answers.clear();
        return apply_rcode(RCODE_ServFail);
    }

    Message&& Message::formerr()
    {
        answers.clear();
        return apply_rcode(RCODE_FormErr);
    }

    Message&& Message::refused()
    {
        answers.clear();
        return apply_rcode(RCODE_Refused);
    }

    Message&& Message::nxdomain(bool authoritative) { return apply_rcode(RCODE_NxDomain, authoritative); }

    std::optional<RawMessage> RawMessage::parse(std::span<const std::byte> buf)
    {
        auto result = std::make_optional<RawMessage>();
        auto& m = *result;

        uint16_t qd_count, an_count, ns_count, ar_count;
        if (!extract_ints(buf, m.hdr_id, m.hdr_fields, qd_count, an_count, ns_count, ar_count))
        {
            log::debug(logcat, "Failed to parse DNS header from raw message");
            return std::nullopt;
        }

        m.questions.resize(qd_count);
        m.answers.resize(an_count);
        m.authorities.resize(ns_count);
        m.additional.resize(ar_count);

        for (auto& q : m.questions)
            q.extract(buf);

        for (auto* sect : {&m.answers, &m.authorities, &m.additional})
        {
            for (auto& rr : *sect)
            {
                auto name_bytes = extract_name_data(buf);
                if (!name_bytes)
                {
                    log::debug(logcat, "Failed to extract name data from raw message");
                    return std::nullopt;
                }
                log::trace(logcat, "Extracted name bytes: {}", buffer_printer{*name_bytes});
                rr.name.assign(name_bytes->begin(), name_bytes->end());
                uint16_t typ, cls;
                uint32_t ttl;
                uint16_t rdlen;
                if (!extract_ints(buf, typ, cls, ttl, rdlen))
                {
                    log::debug(logcat, "Failed to extract type/class/ttl/len");
                    return std::nullopt;
                }
                rr.type = static_cast<RRType>(typ);
                rr.cls = static_cast<RRClass>(cls);
                rr.ttl = std::chrono::seconds{ttl};
                if (buf.size() < rdlen)
                {
                    log::debug(logcat, "Buffer is too short: {} remaining but rdlen={}", buf.size(), rdlen);
                    return std::nullopt;
                }
                rr.rdata.assign(buf.data(), buf.data() + rdlen);
                buf = buf.subspan(rdlen);
            }
        }

        return result;
    }

    void RawMessage::rewrite_for(const Message& orig)
    {
        // We need to rewrite a few things here:
        // - replace hdr_id
        // - update/replace hdr_fields
        //   - AD should be preserved only if the client used EDNS and had the DO bit set, else
        //     cleared.
        //   - CD/RD should be copied from the original client message
        //   - Clear the TC flag.  (We can set if, if needed, when encoding)
        // - strip TSIG additional section, if present.
        // - If the original request used EDNS, replace or append the OPT section in additional
        // - Else strip the OPT from additional, if present.

        hdr_id = orig.hdr_id;
        if (!orig.additional_edns || !orig.additional_edns->DO_bit())
            hdr_fields &= ~flags_AD;
        hdr_fields &= ~(flags_CD | flags_RD | flags_TC);
        hdr_fields |= orig.hdr_fields & flags_CD;
        hdr_fields |= orig.hdr_fields & flags_RD;

        for (auto it = additional.begin(); it != additional.end();)
        {
            if (it->type == RRType::OPT || it->type == RRType::TSIG)
                it = additional.erase(it);
            else
                ++it;
        }

        additional_edns = orig.additional_edns;
    }

    std::vector<std::byte> RawMessage::encode(bool max_size) const
    {
        std::vector<std::byte> tmp;
        tmp.resize(
            max_size              ? std::numeric_limits<uint16_t>::max()
                : additional_edns ? additional_edns->max_payload()
                                  : 512);

        std::span<std::byte> buf{tmp};

        std::optional<RawRR> edns;
        if (additional_edns)
            edns = additional_edns->to_raw();

        write_ints_into(
            buf,
            hdr_id,
            hdr_fields,
            static_cast<uint16_t>(questions.size()),
            static_cast<uint16_t>(answers.size()),
            static_cast<uint16_t>(authorities.size()),
            static_cast<uint16_t>(additional.size() + (edns ? 1 : 0)));

        size_t header_end = buf.data() - tmp.data();

        bool truncate = false;

        for (auto& q : questions)
        {
            try
            {
                encode_name(buf, q.name(), nullptr, nullptr);
                write_ints_into(buf, static_cast<uint16_t>(q.qtype), static_cast<uint16_t>(q.qclass));
            }
            catch (const std::out_of_range&)
            {
                truncate = true;
                break;
            }
        }

        if (truncate)
            log::warning(
                logcat, "Unexpected DNS error: can't find question into {}-byte response message?!", tmp.size());

        // If we fail to write the later sections, we'll back up to here so that we can at least
        // write the EDNS RR in the additional section:
        size_t q_end = truncate ? 0 : buf.data() - tmp.data();

        auto write_section = [&](std::span<const RawRR> section) {
            if (truncate)
                return;
            for (const auto& rr : section)
                if (!rr.write_to(buf))
                {
                    truncate = true;
                    return;
                }
        };

        for (auto* sect : {&answers, &authorities, &additional})
            if (!truncate)
                write_section(*sect);

        if (!truncate && edns)
            // Append the EDNS (OPT RR) to the end of additional; this *could* cause truncation
            // which is why we need to do it here and then try again (under truncate) below.
            write_section({&*edns, 1});

        if (truncate)
        {
            // We couldn't fit the entire reply, so we need to:
            // - set the TC (truncate) bit in the header flags
            oxenc::write_host_as_big(hdr_fields | flags_TC, tmp.data() + 2);

            // - throw away any answers/authorities/additionals by backing up to the end of the
            //   question section.
            buf = std::span{tmp.data() + q_end, tmp.size() - q_end};

            // - If we couldn't even write the question (which is very strange) then reset the
            //   question count to 0 and reset the buffer even further back to the end of the
            //   header:
            if (q_end == 0) [[unlikely]]
            {
                buf = std::span{tmp.data() + header_end, tmp.size() - header_end};
                oxenc::write_host_as_big(uint16_t{0}, tmp.data() + 4);  // question count
            }

            // - Set the answers, authorities counts to 0
            oxenc::write_host_as_big(uint16_t{0}, tmp.data() + 6);  // answer count
            oxenc::write_host_as_big(uint16_t{0}, tmp.data() + 8);  // authority count

            // - Set the additional count to 1 if we have EDNS info, 0 otherwise.
            oxenc::write_host_as_big(edns ? uint16_t{1} : uint16_t{0}, tmp.data() + 10);  // additional count

            // - Write the EDNS (OPT) RR for the additional section
            //   - If *this* fails to write then also reset additional to 0
            if (edns && !edns->write_to(buf))
                oxenc::write_host_as_big(uint16_t{0}, tmp.data() + 10);  // additional count
        }

        // Trim the excess:
        tmp.resize(tmp.size() - buf.size());
        tmp.shrink_to_fit();
        return tmp;
    }

}  // namespace srouter::dns
