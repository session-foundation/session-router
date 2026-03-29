#include <catch2/catch_test_macros.hpp>
#include <sr/node/events.hpp>

using namespace sr::node;

TEST_CASE("EventBus emits to subscriber", "[node][events]")
{
    EventBus bus;
    int called = 0;
    bus.on(Event::PATH_BUILT, [&](Event e, const EventData&) {
        REQUIRE(e == Event::PATH_BUILT);
        ++called;
    });
    bus.emit(Event::PATH_BUILT);
    REQUIRE(called == 1);
}

TEST_CASE("EventBus multiple subscribers", "[node][events]")
{
    EventBus bus;
    int a = 0, b = 0;
    bus.on(Event::PATH_DIED, [&](Event, const EventData&) { ++a; });
    bus.on(Event::PATH_DIED, [&](Event, const EventData&) { ++b; });
    bus.emit(Event::PATH_DIED);
    REQUIRE(a == 1);
    REQUIRE(b == 1);
}

TEST_CASE("EventBus different events don't cross", "[node][events]")
{
    EventBus bus;
    int path_count = 0, session_count = 0;
    bus.on(Event::PATH_BUILT, [&](Event, const EventData&) { ++path_count; });
    bus.on(Event::SESSION_ESTABLISHED, [&](Event, const EventData&) { ++session_count; });

    bus.emit(Event::PATH_BUILT);
    REQUIRE(path_count == 1);
    REQUIRE(session_count == 0);

    bus.emit(Event::SESSION_ESTABLISHED);
    REQUIRE(path_count == 1);
    REQUIRE(session_count == 1);
}

TEST_CASE("EventBus emit with no subscribers is safe", "[node][events]")
{
    EventBus bus;
    bus.emit(Event::BOOTSTRAP_COMPLETE);  // no crash
}

TEST_CASE("EventBus passes data to handler", "[node][events]")
{
    EventBus bus;
    size_t received = 0;
    bus.on(Event::RC_UPDATED, [&](Event, const EventData& data) {
        if (auto* val = std::get_if<size_t>(&data))
            received = *val;
    });
    bus.emit(Event::RC_UPDATED, size_t{42});
    REQUIRE(received == 42);
}

TEST_CASE("EventBus multiple emits", "[node][events]")
{
    EventBus bus;
    int count = 0;
    bus.on(Event::PATH_EXPIRED, [&](Event, const EventData&) { ++count; });
    bus.emit(Event::PATH_EXPIRED);
    bus.emit(Event::PATH_EXPIRED);
    bus.emit(Event::PATH_EXPIRED);
    REQUIRE(count == 3);
}
