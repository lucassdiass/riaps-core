//
// Created by istvan on 2/27/17.
//

#ifndef RIAPS_CORE_RFW_CONFIGURATION_H
#define RIAPS_CORE_RFW_CONFIGURATION_H


#include <const/r_const.h>
#include <string>

namespace riaps {
    namespace framework {
        class Configuration{
        public:
            static std::string GetDiscoveryEndpoint();
            static std::string GetDeviceManagerEndpoint();
            static std::string GetDeploEndpoint();
        };
    }
}


#endif
