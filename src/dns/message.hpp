#pragma once

#include "address/types.hpp"
#include "question.hpp"
#include "rr.hpp"

#include <optional>

namespace srouter
{
    struct IPPacket;

    namespace dns
    {
        struct SRVData;

        // Class representing a DNS question and response as returned by Session Router for local
        // Session Router results (e.g. querying .sesh addresses).
        struct Message
        {
            Message() = default;
            explicit Message(Question question);

            // Non-copyable; see clone() if you want a copy with just the question.
            Message(const Message&) = delete;

            Message(Message&&) = default;

            // Clones the message with question/flags/edns response data, but with no answers
            Message clone() const;

            static constexpr auto DEFAULT_ANSWER_TTL = 10s;

            // These two methods mutates the message into a SERVFAIL/FORMERR/REFUSED response code,
            // clearing all answers.  These return an value reference to the object itself to allow
            // the call to operator like an implicit `std::move()` call as this is typically a final
            // operation; in particular this means: `f(msg.servfail());` is equivalent to
            // `msg.servfail(); f(std::move(msg));`.
            Message&& servfail();
            Message&& formerr();
            Message&& refused();

            // Mutate message into a NXDOMAIN but without clearing existing answers.  Returns an
            // rvalue reference to the current object to allow the result to be easily moved away.
            //
            // The message with include the authoritative flag (AA) if the argument is omitted (or
            // true), and omit it if false.
            Message&& nxdomain(bool authoritative = true);

            // This clears any answers and sets the appropriate header flags for a BADCOOKIE
            // response.  Note that this is only valid when the message has `additional_edns` as
            // part of this error code value is carried in that additional RR data.
            void set_badcookie_flags();

            // Sets the RR name for future added entries, or resets it to default with nullopt.  The
            // default (if not called or reset) is to use the question's name value.  Once set, the
            // value persists for any added answers until this method is called again.
            void set_rr_name(std::optional<std::string> name);
            std::string_view get_rr_name() const
            {
                return rr_name_override ? *rr_name_override : question ? question->qname : ""sv;
            }

            void add_nodata_reply();

            void add_cname_reply(std::string_view name, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            // Adds an 'IN A' reply containing the given ipv4 address
            void add_reply(const ipv4& addr, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);
            // Adds an 'IN AAAA' reply containing the given ipv6 address
            void add_reply(const ipv6& addr, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_reply(const SRVData& srv, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_txt_reply(std::string_view value, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_ptr_reply(std::string_view name, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            // Encodes a response.  If max_size is true then we allow up to 65535 bytes for the
            // response, otherwise we allow either the EDNS max payload (up to 1232), or 512
            // (without EDNS in the query).
            std::vector<std::byte> encode(bool max_size = false) const;

            // Parses a question Message from the given buf, removing the question from the prefix
            // of buf.  `server_cookie_secret` and `client_addr` contains information needed for DNS
            // cookie handling; `server_cookie_secret` is something derived from the SR private key
            // seed + startup time, while client_addr is the raw bytes of the IP address (4 or 16
            // bytes for IPv4/IPv6, respectively).
            //
            // Returns nullopt if the request cannot be parsed at all; returns a Message with
            // `bad_extract` set to true if it was parseable but not valid and should be immediately
            // replied to with an error (which will already be set up in the returned Message
            // object).
            static std::optional<Message> extract_question(
                std::span<const std::byte>& buf,
                std::span<const std::byte, 16> server_cookie_secret,
                std::span<const std::byte> client_addr);

            // See extract_question, above.
            bool bad_extract{false};

            std::string to_string() const;

            uint16_t hdr_id;
            uint16_t hdr_fields;

            std::optional<Question> question;
            std::vector<std::unique_ptr<ResourceRecord>> answers;
            std::vector<std::unique_ptr<ResourceRecord>> authorities;

            // Currently unused:
            // std::vector<ResourceRecord> additional;

            // Currently the only additional record we do anything with is the OPT section for
            // enabling EDNS (most significantly for allowing large DNS packets)
            std::optional<PRR_EDNS> additional_edns;

            std::optional<std::string> rr_name_override;

          private:
            void add_reply(RRClass cls, RRType type, std::vector<std::byte> data, std::chrono::seconds ttl);

            Message&& apply_rcode(uint16_t rcode, bool authoritative = false);
        };

        // Somewhat similar to the above, but only designed for passing through a message (with
        // a few required modifications) rather than building one.
        struct RawMessage
        {
            uint16_t hdr_id;
            uint16_t hdr_fields;
            std::vector<Question> questions;
            std::vector<RawRR> answers;
            std::vector<RawRR> authorities;
            std::vector<RawRR> additional;

            /// Parses a DNS message; returns nullopt if unparseable.  Unlike Message, this parsing
            /// only performs a raw parsing (i.e. there is no interpretation of values).
            static std::optional<RawMessage> parse(std::span<const std::byte> msg);

            // Does some minor rewriting of the raw message according to the given Message that lead
            // to the query.  This includes updating the header id to match, updating fields to
            // match the request, and removing EDNS or TSIG additional value.  If the original
            // message has an additional_edns value, it is copied into this object's additional_edns
            // to be appended during encoding.
            void rewrite_for(const Message& orig);

            std::optional<PRR_EDNS> additional_edns;

            std::vector<std::byte> encode(bool max_size = false) const;
        };

    }  // namespace dns

}  // namespace srouter
