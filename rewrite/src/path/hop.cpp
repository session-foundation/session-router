#include <sr/path/hop.hpp>

#include <sodium.h>

namespace sr::path {

HopID random_hop_id() {
    sr::crypto::sodium_init_once();
    HopID id;
    randombytes_buf(id.data(), id.size());
    return id;
}

}  // namespace sr::path
