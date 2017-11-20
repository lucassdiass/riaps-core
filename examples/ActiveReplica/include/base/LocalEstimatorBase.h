//
// Created by istvan on 3/10/17.
//

#ifndef RIAPS_CORE_LOCALESTIMATORBASE_H
#define RIAPS_CORE_LOCALESTIMATORBASE_H

#include "componentmodel/r_componentbase.h"
#include "messages/activereplica.capnp.h"
#include "GroupTypes.h"

// Name of the ports from the model file
#define PORT_SUB_READY    "ready"
#define PORT_REQ_QUERY    "query"
#define PORT_PUB_ESTIMATE "estimate"



namespace activereplica {
    namespace components {

        class LocalEstimatorBase : public riaps::ComponentBase {

        public:

            LocalEstimatorBase(_component_conf &config, riaps::Actor &actor);

            //virtual void RegisterHandlers();

            virtual void OnReady(const messages::SensorReady::Reader &message,
                                 riaps::ports::PortBase *port)=0;

            // I think we don't need handler for the request port. Request-Response should be sync anyway.
            // The real async is router-dealer
            //
            //virtual void OnQuery(const std::string& messagetype,
            //                     std::vector<std::string>& msgFields,
            //                     riaps::ports::PortBase* port)=0;


            bool SendQuery(capnp::MallocMessageBuilder&    messageBuilder,
                           messages::SensorQuery::Builder& message);

            bool RecvQuery(messages::SensorValue::Reader &message);

            bool SendEstimate(capnp::MallocMessageBuilder& messageBuilder,
                              messages::Estimate::Builder& message);


            virtual ~LocalEstimatorBase();

        protected:
            virtual void DispatchMessage(capnp::FlatArrayMessageReader* capnpreader,
                                         riaps::ports::PortBase *port);

            virtual void DispatchInsideMessage(zmsg_t* zmsg,
                                               riaps::ports::PortBase* port);

        };
    }
}

#endif //RIAPS_CORE_LOCALESTIMATORBASE_H
