//
// Created by istvan on 5/5/17.
//

#include <device/r_deviceactor.h>
#include <const/r_jsonmodel.h>
#include <componentmodel/r_argumentparser.h>

namespace riaps{

    DeviceActor::DeviceActor(const std::string&     applicationname       ,
                             const std::string&     actorname             ,
                             nlohmann::json& jsonActorconfig             ,
                             nlohmann::json& jsonComponentsconfig         ,
                             nlohmann::json& jsonDevicesconfig            ,
                             nlohmann::json& jsonMessagesconfig          ,
                             std::map<std::string, std::string>& commandLineParams)
            : Actor(applicationname,
                    actorname,
                    jsonActorconfig,
                    jsonComponentsconfig,
                    jsonDevicesconfig,
                    jsonMessagesconfig,
                    commandLineParams) {
        _startDevice = true;

    }

    DeviceActor* DeviceActor::CreateDeviceActor(nlohmann::json& configJson,
                                                const std::string& actorName,
                                                std::map<std::string, std::string>& actualParams) {

        std::string applicationName    = configJson[J_NAME];
        nlohmann::json jsonActors      = configJson[J_ACTORS];
        nlohmann::json jsonComponents  = configJson[J_COMPONENTS];
        nlohmann::json jsonDevices     = configJson[J_DEVICES];
        nlohmann::json jsonMessages    = configJson[J_MESSAGES];

        // Find the actor
        if (jsonActors.find(actorName)==jsonActors.end()){
            std::cerr << "Didn't find actor in the model file: " << actorName << std::endl;
            return NULL;
        }

        auto jsonCurrentActor = jsonActors[actorName];

        return new ::riaps::DeviceActor(
                applicationName,
                actorName,
                jsonCurrentActor,
                jsonComponents,
                jsonDevices,
                jsonMessages,
                actualParams
        );



    }

    DeviceActor::~DeviceActor() {

    }
}