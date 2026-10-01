extern "C"
{
#include <wintun.h>
}

#include "dll.hpp"
#include "exception.hpp"
#include "guid.hpp"
#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/str.hpp"
#include "util/thread/queue.hpp"
#include "vpn/platform.hpp"
#include "wintun.hpp"

#include <iphlpapi.h>

#include <map>
#include <unordered_set>
#include <span>
#include <cstring>
#include <variant>

namespace srouter::win32
{
    namespace
    {
        static auto logcat = log::Cat("wintun");
        constexpr auto PoolName = "session-router";

        WINTUN_CREATE_ADAPTER_FUNC* create_adapter = nullptr;
        WINTUN_CLOSE_ADAPTER_FUNC* close_adapter = nullptr;
        WINTUN_OPEN_ADAPTER_FUNC* open_adapter = nullptr;
        WINTUN_GET_ADAPTER_LUID_FUNC* get_adapter_LUID = nullptr;
        WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* get_version = nullptr;
        WINTUN_DELETE_DRIVER_FUNC* delete_driver = nullptr;
        WINTUN_SET_LOGGER_FUNC* set_logger = nullptr;
        WINTUN_START_SESSION_FUNC* start_session = nullptr;
        WINTUN_END_SESSION_FUNC* end_session = nullptr;
        WINTUN_GET_READ_WAIT_EVENT_FUNC* get_adapter_handle = nullptr;
        WINTUN_RECEIVE_PACKET_FUNC* read_packet = nullptr;
        WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release_read = nullptr;
        WINTUN_ALLOCATE_SEND_PACKET_FUNC* alloc_write = nullptr;
        WINTUN_SEND_PACKET_FUNC* send_packet = nullptr;

        void WintunInitialize()
        {
            if (create_adapter)
                return;

            // clang-format off
      load_dll_functions(
          "wintun.dll",

          "WintunCreateAdapter",            create_adapter,
          "WintunCloseAdapter",             close_adapter,
          "WintunOpenAdapter",              open_adapter,
          "WintunGetAdapterLUID",           get_adapter_LUID,
          "WintunGetRunningDriverVersion",  get_version,
          "WintunDeleteDriver",             delete_driver,
          "WintunSetLogger",                set_logger,
          "WintunStartSession",             start_session,
          "WintunEndSession",               end_session,
          "WintunGetReadWaitEvent",         get_adapter_handle,
          "WintunReceivePacket",            read_packet,
          "WintunReleaseReceivePacket",     release_read,
          "WintunAllocateSendPacket",       alloc_write,
          "WintunSendPacket",               send_packet);
            // clang-format on
        }

        using Adapter_ptr = std::shared_ptr<_WINTUN_ADAPTER>;

        struct PacketWrapper
        {
            BYTE* data;
            DWORD size;
            WINTUN_SESSION_HANDLE session;
            /// copy our data into an ip packet struct
            IPPacket copy() const
            {
                return IPPacket{
                    std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), static_cast<size_t>(size)}};
            }

            ~PacketWrapper() { release_read(session, data); }
        };

        /// autovivify a wintun adapter handle
        [[nodiscard]] auto make_adapter(std::string adapter_name, std::string tunnel_name)
        {
            auto adapter_name_wide = to_wide(adapter_name);
            if (auto _impl = open_adapter(adapter_name_wide.c_str()))
            {
                log::info(logcat, "opened existing adapter: '{}'", adapter_name);
                return _impl;
            }
            if (auto err = GetLastError())
            {
                log::info(logcat, "did not open existing adapter '{}': {}", adapter_name, error_to_string(err));
                SetLastError(0);
            }
            const auto guid = srouter::win32::MakeDeterministicGUID(fmt::format("{}|{}", adapter_name, tunnel_name));
            log::info(logcat, "creating adapter: '{}' on pool '{}'", adapter_name, tunnel_name);
            auto tunnel_name_wide = to_wide(tunnel_name);
            if (auto _impl = create_adapter(adapter_name_wide.c_str(), tunnel_name_wide.c_str(), &guid))
            {
                if (auto v = get_version())
                    log::info(logcat, "created adapter (wintun v{}.{})", (v >> 16) & 0xff, v & 0xff);
                else
                    log::warning(logcat, "failed to query wintun driver version: {}!", error_to_string(GetLastError()));
                return _impl;
            }

            throw win32::error{"failed to create wintun adapter"};
        }

        class WintunAdapter
        {
            WINTUN_ADAPTER_HANDLE _handle;

            [[nodiscard]] auto GetAdapterLUID() const
            {
                NET_LUID _uid{};
                get_adapter_LUID(_handle, &_uid);
                return _uid;
            }

          public:
            explicit WintunAdapter(std::string name)
            {
                _handle = make_adapter(std::move(name), PoolName);
                if (_handle == nullptr)
                    throw std::runtime_error{"failed to create wintun adapter"};
            }

            /// put adapter up
            void Up(const vpn::InterfaceInfo& info) const
            {
                const auto luid = GetAdapterLUID();
                // WintunCreateAdapter can return before the InterfaceLuid is visible to
                // IP Helper. CreateUnicastIpAddressEntry then returns ERROR_NOT_FOUND
                // (1168). Retry with short backoff; treat 5010 (already exists) as success.
                // CreateUnicastIpAddressEntry may mutate the row on failure; restore a
                // clean copy each attempt so a retry cannot AV on a half-filled struct.
                // IPv6: byte-stable SOCKADDR_INET fill (MSVC sin6_addr @ +8). Never declare
                // a named IN6 sockaddr local or write via the Address Ipv6 union member.
                auto set_unicast_v4 = [](const MIB_UNICASTIPADDRESS_ROW& prototype, const auto& label) {
                    DWORD err = ERROR_SUCCESS;
                    for (int attempt = 0; attempt < 50; ++attempt)
                    {
                        MIB_UNICASTIPADDRESS_ROW row = prototype;
                        err = CreateUnicastIpAddressEntry(&row);
                        if (err == ERROR_SUCCESS || err == 5010)
                            return;
                        if (err != ERROR_NOT_FOUND)
                            break;
                        Sleep(50);
                    }
                    throw win32::error{err, fmt::format("cannot set address '{}'", label)};
                };
                auto set_unicast_v6 = [](const MIB_UNICASTIPADDRESS_ROW& prototype, const auto& label) {
                    DWORD err = ERROR_SUCCESS;
                    for (int attempt = 0; attempt < 50; ++attempt)
                    {
                        MIB_UNICASTIPADDRESS_ROW row = prototype;
                        err = CreateUnicastIpAddressEntry(&row);
                        if (err == ERROR_SUCCESS || err == 5010)
                            return;
                        if (err != ERROR_NOT_FOUND)
                            break;
                        Sleep(50);
                    }
                    throw win32::error{err, fmt::format("cannot set address '{}'", label)};
                };
                for (const auto& addr : info.addrs)
                {
                    MIB_UNICASTIPADDRESS_ROW AddressRow;
                    InitializeUnicastIpAddressEntry(&AddressRow);
                    AddressRow.InterfaceLuid = luid;
                    AddressRow.DadState = IpDadStatePreferred;

                    if (const auto* n4 = std::get_if<ipv4_net>(&addr))
                    {
                        AddressRow.Address.Ipv4.sin_family = AF_INET;
                        AddressRow.Address.Ipv4.sin_addr = static_cast<in_addr>(n4->ip);
                        AddressRow.OnLinkPrefixLength = n4->mask;

                        set_unicast_v4(AddressRow, n4->to_string());
                        log::debug(logcat, "Added address: {}", n4->to_string());
                    }
                    else if (const auto* n6 = std::get_if<ipv6_net>(&addr))
                    {
                        // Byte-stable MSVC SOCKADDR_INET layout: si_family @0, sin6_addr @8.
                        std::memset(&AddressRow.Address, 0, sizeof(AddressRow.Address));
                        AddressRow.Address.si_family = AF_INET6;
                        const in6_addr v6 = static_cast<in6_addr>(n6->ip);
                        std::memcpy(reinterpret_cast<unsigned char*>(&AddressRow.Address) + 8, &v6, 16);
                        AddressRow.OnLinkPrefixLength = n6->mask;

                        set_unicast_v6(AddressRow, n6->to_string());
                        log::debug(logcat, "Added address: {}", n6->to_string());
                    }
                }
            }

            /// put adapter down and close it
            void Down() const { close_adapter(_handle); }

            /// auto vivify a wintun session handle and read handle off of our adapter
            [[nodiscard]] std::pair<WINTUN_SESSION_HANDLE, HANDLE> session() const
            {
                if (auto wintun_ver = get_version())
                    log::info(
                        logcat,
                        fmt::format("wintun version {}.{} loaded", (wintun_ver >> 16) & 0xff, wintun_ver & 0xff));
                else
                    throw win32::error{"Failed to load wintun"};
                if (auto impl = start_session(_handle, WINTUN_MAX_RING_CAPACITY))
                {
                    if (auto handle = get_adapter_handle(impl))
                        return {impl, handle};
                    end_session(impl);
                }
                return {nullptr, nullptr};
            }
        };

        class WintunSession
        {
            WINTUN_SESSION_HANDLE _impl;
            HANDLE _handle;
            std::atomic<bool> ended{false};
            static_assert(std::atomic<bool>::is_always_lock_free);

          public:
            WintunSession() : _impl{nullptr}, _handle{nullptr} {}

            void Start(const std::shared_ptr<WintunAdapter>& adapter)
            {
                if (auto [impl, handle] = adapter->session(); impl and handle)
                {
                    _impl = impl;
                    _handle = handle;
                    return;
                }
                throw error{GetLastError(), "could not create wintun session"};
            }

            void Stop()
            {
                ended = true;
                end_session(_impl);
            }

            void WaitFor(std::chrono::milliseconds dur) { WaitForSingleObject(_handle, dur.count()); }

            /// read a unique pointer holding a packet read from wintun, returns the packet if we
            /// read one and a bool, set to true if our adapter is now closed
            [[nodiscard]] std::pair<std::unique_ptr<PacketWrapper>, bool> ReadPacket() const
            {
                if (ended)
                    return {nullptr, true};
                DWORD sz;
                if (auto* ptr = read_packet(_impl, &sz))
                    return {std::unique_ptr<PacketWrapper>{new PacketWrapper{ptr, sz, _impl}}, false};
                const auto err = GetLastError();
                if (err == ERROR_NO_MORE_ITEMS or err == ERROR_HANDLE_EOF)
                {
                    SetLastError(0);
                    return {nullptr, err == ERROR_HANDLE_EOF};
                }
                throw error{err, "failed to read packet"};
            }

            /// write an ip packet to the interface, return 2 bools, first is did we write the
            /// packet, second if we are terminating
            std::pair<bool, bool> WritePacket(IPPacket pkt) const
            {
                if (auto* buf = alloc_write(_impl, pkt.size()))
                {
                    std::memcpy(buf, pkt.data(), pkt.size());
                    send_packet(_impl, buf);
                    return {true, false};
                }
                const auto err = GetLastError();
                if (err == ERROR_BUFFER_OVERFLOW or err == ERROR_HANDLE_EOF)
                {
                    SetLastError(0);
                    return {err != ERROR_BUFFER_OVERFLOW, err == ERROR_HANDLE_EOF};
                }
                throw error{err, "failed to write packet"};
            }
        };

        class WintunInterface : public vpn::NetworkInterface
        {
            Router* const _router;
            std::shared_ptr<WintunAdapter> _adapter;
            std::shared_ptr<WintunSession> _session;
            thread::Queue<IPPacket> _recv_queue;
            thread::Queue<IPPacket> _send_queue;
            std::thread _recv_thread;
            std::thread _send_thread;

            inline static constexpr size_t packet_queue_length = 1024;

          public:
            WintunInterface(vpn::InterfaceInfo info, Router* router)
                : vpn::NetworkInterface{std::move(info)},
                  _router{router},
                  _adapter{std::make_shared<WintunAdapter>(_info.ifname)},
                  _session{std::make_shared<WintunSession>()},
                  _recv_queue{packet_queue_length},
                  _send_queue{packet_queue_length}
            {}

            void Start() override
            {
                _info.index = 0;
                // put the adapter and set addresses
                _adapter->Up(_info);
                // start up io session
                _session->Start(_adapter);

                // start read packet loop
                _recv_thread = std::thread{[session = _session, this]() {
                    do
                    {
                        // read all our packets this iteration
                        bool more{true};
                        do
                        {
                            auto [pkt, done] = session->ReadPacket();
                            // bail if we are closing
                            if (done)
                                return;
                            if (pkt)
                                _recv_queue.pushBack(pkt->copy());
                            else
                                more = false;
                        } while (more);
                        // wait for more packets
                        session->WaitFor(5s);
                    } while (true);
                }};
                // start write packet loop
                _send_thread = std::thread{[this, session = _session]() {
                    do
                    {
                        if (auto maybe = _send_queue.popFrontWithTimeout(100ms))
                        {
                            auto [written, done] = session->WritePacket(std::move(*maybe));
                            if (done)
                                return;
                        }
                    } while (_send_queue.enabled());
                }};
            }

            void Stop() override
            {
                // end writing packets
                _send_queue.disable();
                _send_thread.join();
                // end reading packets
                _session->Stop();
                _recv_thread.join();
                // close session
                _session.reset();
                // put adapter down
                _adapter->Down();
                _adapter.reset();
            }

            IPPacket read_next_packet() override
            {
                IPPacket pkt{};
                if (auto maybe_pkt = _recv_queue.tryPopFront())
                    pkt = std::move(*maybe_pkt);
                return pkt;
            }

            bool write_packet(IPPacket pkt) override
            {
                return _send_queue.tryPushBack(std::move(pkt)) == thread::QueueReturn::Success;
            }

            int PollFD() const override { return -1; }

            void MaybeWakeUpperLayers() const override
            {
                // Router wake/pump API removed; apple leaves this empty.
            }
        };
    }  // namespace

    namespace wintun
    {
        std::shared_ptr<vpn::NetworkInterface> make_interface(
            const srouter::vpn::InterfaceInfo& info, srouter::Router* r)
        {
            WintunInitialize();
            return std::static_pointer_cast<vpn::NetworkInterface>(std::make_shared<WintunInterface>(info, r));
        }
    }  // namespace wintun

}  // namespace srouter::win32
