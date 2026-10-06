#pragma once

#include "encode.hpp"
#include "srv_data.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <span>
#include <vector>

namespace srouter::dns
{
    enum class RRClass : uint16_t
    {
        IN = 1,
    };
    enum class RRType : uint16_t
    {
        A = 1,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        TXT = 16,
        AAAA = 28,
        SRV = 33,

        OPT = 41,
        TSIG = 250,
    };

    // Parsed RR data: this is intentionally very raw and is only for extracting the data, not
    // interpreting it.  Note that the rdata value points into the input buf: the ParsedRR data
    // should not be held longer than the input buffer!
    struct ParsedRR
    {
        std::string name;
        RRType rr_type;    // *Not* necessarily one of the values defined above
        RRClass rr_class;  // *Not* necessarily one of the values defined above
        std::chrono::seconds ttl;
        std::span<const std::byte> rdata;

        // Attempts to parse an RR from the beginning of `buf`.  `buf` will have the prefix removed
        // containing the extracted record.  Returns nullopt on extraction error.
        static std::optional<ParsedRR> extract(std::span<const std::byte>& buf);
    };

    // Unparsed RR data: this is used by RawMessage to hold the basic raw data of an RR, but without
    // decoding non-integer binary values.  That is, the NAME and RDATA are encoded exactly as
    // provided (and so may have name compression pointers in them).  This is designed so that it
    // can be re-encoded in a byte-exact way (to avoid breaking compressed name values that may be
    // in this or later RRs).
    struct RawRR
    {
        std::vector<std::byte> name;
        RRType type;
        RRClass cls;
        std::chrono::seconds ttl;
        std::vector<std::byte> rdata;

        // Writes this RR data into `buf`, removing the written prefix from buf and returns true.
        // If buf does not have enough room for the entire record then nothing is written, buf is
        // not modified, and false is returned.
        bool write_to(std::span<std::byte>& buf) const;
    };

    // Abstract base class we use for building RR responses
    struct ResourceRecord
    {
        ResourceRecord(std::string rr_name, std::chrono::seconds ttl) : rr_name{std::move(rr_name)}, ttl{ttl} {}

        virtual ~ResourceRecord() = default;

        // Writes this RR to the beginning of buf, eliminating the written section from buf.  Throws if buf is exceeded.
        //
        // This takes care of the basic stuff (name, type, class, ttl), then calls the virtual
        // encode_data() to write the value.
        void encode(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const;

        virtual void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const = 0;

        nlohmann::json ToJSON() const;

        std::string to_string() const;

        std::string rr_name;
        RRClass rr_class = RRClass::IN;
        std::chrono::seconds ttl;

        virtual RRType rr_type() const = 0;

        static constexpr bool to_string_formattable = true;
    };

    // Subclass of ResourceRecord that just has a binary check of data.  Should not be used for data
    // types containing compressible names in the value.  The subclass must take care of encoding
    // the rData member value as required; this base class encode_data simply barfs it into the
    // buffer as-is.
    struct RR_bytes : ResourceRecord
    {
        std::vector<std::byte> rData;

        using ResourceRecord::ResourceRecord;

        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };

    struct RR_A : RR_bytes
    {
        RR_A(std::string rr_name, std::chrono::seconds ttl, const ipv4& addr);
        RRType rr_type() const override { return RRType::A; }
    };
    struct RR_AAAA : RR_bytes
    {
        RR_AAAA(std::string rr_name, std::chrono::seconds ttl, const ipv6& addr);
        RRType rr_type() const override { return RRType::AAAA; }
    };
    struct RR_TXT : RR_bytes
    {
        RR_TXT(std::string rr_name, std::chrono::seconds ttl, std::string_view value);
        RRType rr_type() const override { return RRType::TXT; }
    };
    struct RR_SOA : RR_bytes
    {
        // SOA records consist of:
        // - MNAME -- "master name server", a DNS name (e.g. localhost.sesh).  We don't require a
        //   trailing .
        // - RNAME -- "responsible party", an e-mail address (but with @ replaced with a .) back in
        //   1987's naïve version of the internet, and basically always ignored even back then.  We
        //   don't require a trailing .
        // - SERIAL -- should change whenever records change.  In SR we just increment it on every
        //   request.
        // - MINIMUM -- the TTL for NXDOMAIN and NODATA responses, i.e. the negative caching TTL for
        //   caching DNS servers that get this record.
        // - REFRESH/RETRY/EXPIRY -- how often (in seconds) secondary DNS should wait to
        //   refresh/retry after error/expire data received from the primary.  In SR context these
        //   values are fairly meaningless and are unlikely to be used by anything.
        //
        // (MINIMUM comes after REFRESH/RETRY/EXPIRY in the actual record, but we want to default
        // them and so rearrange constructor arguments).
        RR_SOA(
            std::string rr_name,
            std::chrono::seconds ttl,
            std::string_view mname,
            std::string_view rname,
            uint32_t serial,
            std::chrono::seconds minimum,
            std::chrono::seconds refresh = 1h,
            std::chrono::seconds retry = 15min,
            std::chrono::seconds expire = 14 * 24h);
        RRType rr_type() const override { return RRType::SOA; }
    };

    // Base class for RR types that have a single target name as the value, such as CNAME and PTR
    struct RR_target : ResourceRecord
    {
        std::string name;

        RR_target(std::string rr_name, std::chrono::seconds ttl, std::string name)
            : ResourceRecord{std::move(rr_name), ttl}, name{std::move(name)}
        {}

        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };

    struct RR_PTR : RR_target
    {
        using RR_target::RR_target;
        RRType rr_type() const override { return RRType::PTR; }
    };
    struct RR_CNAME : RR_target
    {
        using RR_target::RR_target;
        RRType rr_type() const override { return RRType::CNAME; }
    };
    struct RR_SRV : ResourceRecord
    {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        std::string target;

        RR_SRV(std::string rr_name, std::chrono::seconds ttl, const SRVData& srv)
            : ResourceRecord{std::move(rr_name), ttl},
              priority{srv.priority},
              weight{srv.weight},
              port{srv.port},
              target{srv.target}
        {}

        RRType rr_type() const override { return RRType::SRV; }
        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };

    // Psuedo-RR for EDNS; a client sends this in the additional section if it supports EDNS, and
    // the server sends it back (if provided) to confirm that the server also supports EDNS.
    struct PRR_EDNS : ResourceRecord
    {
        static constexpr uint16_t OPT_COOKIE = 10;
        static constexpr uint16_t EXT_RCODE_BADCOOKIE = 23;

        static constexpr uint32_t DO_BIT = 1 << 15;

        std::optional<std::array<std::byte, 24>> cookie;

        // Will be true if the full cookie we were provided was invalid or expired, in which case we
        // are supposed to immediately fail with an extended BADCOOKIE error code (which will be
        // encoded if this object is encoded into the output with this bool set to true).
        bool bad_cookie{false};

        // Constructs an EDNS value.  This is rather hacky, to try to mash it into the fairly
        // inflexible older DNS protocol:
        // - NAME is always empty (i.e. ".", the root domain)
        // - 32-bit TTL is nothing to do with ttl, but actually 3 packed fields:
        //     - 8-bit "extended rcode"
        //     - 8-bit version (currently 0)
        //     - 16-bit flags of which there is one for DNSSEC and all others are reserved
        // - CLASS isn't a class at all but rather contains the supported UDP payload size.  We set
        //   it to the recommended 1232 size, but if a client gave us a smaller value we should
        //   reflect that instead.
        //
        //   Beyond that, we support an optional DNS server cookie value (see RFC 7873 and 9018),
        //   which must be the 8-byte cookie sent by the client followed by a 16 byte server cookie.
        PRR_EDNS(
            uint16_t max_payload,
            std::chrono::seconds pttl,
            std::optional<std::array<std::byte, 24>> cookie = std::nullopt)
            : ResourceRecord{"", 0s}, cookie{std::move(cookie)}
        {
            // If the psuedo-ttl has the DO bit set then preserve that bit; otherwise we ignore
            // anything in the pseudo-ttl (leaving it at 0):
            if (pttl.count() & DO_BIT)
                ttl = std::chrono::seconds{DO_BIT};
            rr_class = static_cast<RRClass>(max_payload);
        }

        bool DO_bit() const { return ttl.count() & DO_BIT; }

        uint16_t max_payload() const { return static_cast<uint16_t>(rr_class); }
        constexpr RRType rr_type() const override { return RRType::OPT; }
        void encode_data(std::span<std::byte>& buf, prev_names_t&, uint16_t& buf_offset) const override;

        RawRR to_raw() const;
    };

}  // namespace srouter::dns
