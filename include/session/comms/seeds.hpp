#pragma once

#include <array>

#include "session/onionreq/key_types.hpp"
#include "sn_list.hpp"

namespace session::comms {

inline const std::array SEEDS = {
        service_node_contact{
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                "be83fe1221fdd85e4d9d2b62e2a34ba82eaf73da45700185d25aff4575ec6018",
                "144.76.164.202",
                20200},
        service_node_contact{
                "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce",
                "05c8c236cf6c4013b8ca930a343fdc62c413ba038a16bb12e75632e0179d404a",
                "88.99.102.229",
                20201},
        service_node_contact{
                "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f",
                "22ced8efd4e5faf15531e9b9244b2c1de299342892b97d19268c4db69ab6350f",
                "195.16.73.17",
                20202},
        service_node_contact{
                "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b",
                "330ad0d67b58f39a6f46fbeaf5c3622860dfa584e9d787f70c3702031712767a",
                "104.194.11.120",
                20203},
        service_node_contact{
                "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0",
                "929c5fc60efa1834a2d4a77a4a33387c1c3d5afc2b192c2ba0e040b29388b216",
                "104.194.8.115",
                20204},
};

inline const std::array TESTNET_SEEDS = {
        service_node_contact{
                "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed",
                "6a1db6f30e5873bfb26e12e1f624427c16f1bc360db5632db01dadefc74ea730",
                "104.243.40.38",
                35418},
        service_node_contact{
                "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a",
                "af59dda94242e47cfa4dbd9f02fbb70e769418d9706480c6882f2f8e39c4fe5e",
                "23.88.6.250",
                35420},
};

}  // namespace session::comms
