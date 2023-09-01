#include <oxenc/hex.h>

#include <iostream>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "protos.hpp"

int main(int argc, char* argv[]) {
    const std::string _input{
            "08011283040A03505554120F2F6170692F76312F6D6573736167651ADF030806120028CFABB9D99A313801"
            "42CF03C6CD656E03108B59459467AEAE2EFEF8C018B686029C2AD7F2297161EE7980452F1639781683D697"
            "2AB47C9560FBB705ABA5B677C2D363CA017A1AD9B5A8A2E0CF9EEA57B0C2B31E94DB220F573E85A918BF53"
            "5AD3E61523E3CF341C9A9D3A3346A61FA8064DB311BB9EA17B184FC3F543B4F6CAAD96A2598F720D3698FF"
            "71B21D936B30F0C9094E81894C43FBCEB2B9380040183B60E8C7D2498E8228E1E95B48C55D1022BF3FF3E8"
            "0EC46B6ABFB01D63D30E97E465A1F414F89D1692F1B7A74C362BAC543ACFE959B7BC1A24D6D5D4509DD316"
            "3310CD11A6AC7D7AE5FA4D1CDF9456B9E04C6D1D134EFAF03620098644B831CEA445A2AEDA3415E35633DE"
            "382499F57A781D6A2AF07B7AF58E22DEFA52B229A485A7EB1C57BF9FBF7D1CFB6FD254D15E53F5C3F0272A"
            "DABABB20EC5009B28710D5B255829EA863755E748FCC60F5B6C858D1AD36CE5AC5A0041C2398BA06509B6C"
            "FA0ACFA00D9CDCCBD173BE1F1E21E32379CD35BDE891512BFC2E1C16C12E242AD9ABB1583F3D68EA46C2D8"
            "21E792D6EF4F557353D61C7B67E6657F673E421D850577F8E705F46B008685D4A747EA7A51C1BBA4899619"
            "D9AA8A603505851E5B0B8DEE237F5B2868BDE02E5FE785ABA8C290165588126D59D723CD20CA94A298BD92"
            "A8BAB501"};

    auto input = oxenc::from_hex(_input);

    auto msg = WebSocketProtos::WebSocketMessage();

    if (auto b = msg.ParseFromString(input)) {
        auto req = msg.request();
        const auto& data = req.body();
        auto envelope = SessionProtos::Envelope();

        if (auto b = envelope.ParseFromString(
                    {reinterpret_cast<const char*>(data.data()), data.size()})) {
            const auto& content = envelope.content();
            const auto& type = envelope.type();

            std::cout << type << std::endl;

            auto typing = SessionProtos::SharedConfigMessage();

            if (auto t = typing.ParseFromString(
                        {reinterpret_cast<const char*>(data.data()), data.size()})) {
                std::cout << "Message is ConfigurationMessage" << std::endl;
            }
        }

    } else {
        std::cout << "Failed to parse input" << std::endl;
    }
}
