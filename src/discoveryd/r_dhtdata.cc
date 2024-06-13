//
// Created by istvan on 1/24/19.
//
#include <discoveryd/r_dhtdata.h>

namespace riaps {
    namespace discovery {


        void DhtData::EncryptData(std::vector<uint8_t> &data,
                                  std::shared_ptr<dht::crypto::PrivateKey> private_key) {
            auto public_key = private_key->getPublicKey();
            encrypted_data = public_key.encrypt(data);
            signature = private_key->sign(encrypted_data);
        }

        bool DhtData::DecryptData(std::shared_ptr<dht::crypto::PrivateKey> private_key) {
            try {
                if (private_key->getPublicKey().checkSignature(encrypted_data, signature)) {
                    auto data = private_key->decrypt(encrypted_data);
                    raw_data = data;
                    return true;
                }
                return false;
            } catch (dht::crypto::CryptoException &e) {
                return false;
            }
        }

        const dht::ValueType DhtData::TYPE = {3, "RIAPS Data", std::chrono::minutes(10)};

    }
}
