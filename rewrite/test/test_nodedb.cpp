#include <catch2/catch_test_macros.hpp>
#include <sr/contact/nodedb.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::contact;
using namespace sr::crypto;

static RelayContact make_rc()
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    RelayAddress addr{0x0100007F, 1090};
    auto now = std::chrono::system_clock::now();
    RelayContact rc{rid, addr, {0, 10, 0}, now};
    rc.sign(kp.sk);
    return rc;
}

TEST_CASE("NodeDB put and get", "[contact][nodedb]")
{
    NodeDB db;
    auto rc = make_rc();
    db.put_rc(rc);

    REQUIRE(db.size() == 1);
    REQUIRE(db.has_rc(rc.router_id()));
    auto got = db.get_rc(rc.router_id());
    REQUIRE(got.has_value());
    REQUIRE(got->router_id() == rc.router_id());
}

TEST_CASE("NodeDB remove", "[contact][nodedb]")
{
    NodeDB db;
    auto rc = make_rc();
    db.put_rc(rc);
    db.remove_rc(rc.router_id());
    REQUIRE(db.size() == 0);
    REQUIRE_FALSE(db.has_rc(rc.router_id()));
}

TEST_CASE("NodeDB get missing returns nullopt", "[contact][nodedb]")
{
    NodeDB db;
    auto kp = Ed25519KeyPair::generate();
    REQUIRE_FALSE(db.get_rc(RouterID{kp.pk}).has_value());
}

TEST_CASE("NodeDB random_rcs", "[contact][nodedb]")
{
    NodeDB db;
    for (int i = 0; i < 20; ++i)
        db.put_rc(make_rc());

    auto rcs = db.random_rcs(5);
    REQUIRE(rcs.size() == 5);

    // All should be unique
    std::unordered_set<RouterID> seen;
    for (const auto& rc : rcs)
        seen.insert(rc.router_id());
    REQUIRE(seen.size() == 5);
}

TEST_CASE("NodeDB random_rcs with exclusion", "[contact][nodedb]")
{
    NodeDB db;
    std::vector<RelayContact> all;
    for (int i = 0; i < 10; ++i)
    {
        auto rc = make_rc();
        all.push_back(rc);
        db.put_rc(rc);
    }

    std::unordered_set<RouterID> exclude;
    exclude.insert(all[0].router_id());
    exclude.insert(all[1].router_id());

    auto rcs = db.random_rcs(8, exclude);
    REQUIRE(rcs.size() == 8);
    for (const auto& rc : rcs)
    {
        REQUIRE_FALSE(exclude.contains(rc.router_id()));
    }
}

TEST_CASE("NodeDB random_rcs more than available", "[contact][nodedb]")
{
    NodeDB db;
    for (int i = 0; i < 3; ++i)
        db.put_rc(make_rc());

    auto rcs = db.random_rcs(10);
    REQUIRE(rcs.size() == 3);
}

TEST_CASE("NodeDB purge_expired", "[contact][nodedb]")
{
    NodeDB db;

    // Add fresh RC
    auto fresh = make_rc();
    db.put_rc(fresh);

    // Add old RC
    auto kp = Ed25519KeyPair::generate();
    auto old_time = std::chrono::system_clock::now() - std::chrono::hours(2);
    RelayContact old_rc{RouterID{kp.pk}, {0x0100007F, 1090}, {0, 10, 0}, old_time};
    old_rc.sign(kp.sk);
    db.put_rc(old_rc);

    REQUIRE(db.size() == 2);
    size_t purged = db.purge_expired(std::chrono::system_clock::now());
    REQUIRE(purged == 1);
    REQUIRE(db.size() == 1);
    REQUIRE(db.has_rc(fresh.router_id()));
}

TEST_CASE("NodeDB has_min_rcs", "[contact][nodedb]")
{
    NodeDB db;
    REQUIRE_FALSE(db.has_min_rcs(6));

    for (int i = 0; i < 6; ++i)
        db.put_rc(make_rc());
    REQUIRE(db.has_min_rcs(6));
}

TEST_CASE("NodeDB bucket hashes deterministic", "[contact][nodedb]")
{
    NodeDB db;
    for (int i = 0; i < 10; ++i)
        db.put_rc(make_rc());

    auto h1 = db.compute_bucket_hashes();
    auto h2 = db.compute_bucket_hashes();
    REQUIRE(h1 == h2);
}

TEST_CASE("NodeDB bucket hashes change with data", "[contact][nodedb]")
{
    NodeDB db;
    auto rc1 = make_rc();
    db.put_rc(rc1);
    auto h1 = db.compute_bucket_hashes();

    db.put_rc(make_rc());
    auto h2 = db.compute_bucket_hashes();

    REQUIRE(h1 != h2);
}
