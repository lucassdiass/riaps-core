//
// Created by parallels on 9/6/16.
//

#ifndef RIAPS_R_PUBLISHERPORT_H
#define RIAPS_R_PUBLISHERPORT_H

#include "r_componentbase.h"
#include "r_configuration.h"
#include "r_portbase.h"

#include "czmq.h"

#include <string>

namespace riaps {

    class ComponentBase;

    namespace ports {

       class PublisherPort : public PortBase {
       public:

           PublisherPort(_component_port_pub_j &config, ComponentBase *parent_component);

           std::string GetEndpoint();

           _component_port_pub_j* GetConfig();

           virtual void Send(zmsg_t *msg) const;

           // virtual void SendMessage();

           ~PublisherPort();


       protected:
           //_component_port_pub_j _configuration;

           int _port;
           std::string _host;
           std::string _endpoint;
           zsock_t *_discovery_port;
           //zsock_t*              _port_socket;
       };
   }
}

#endif //RIAPS_R_PUBLISHERPORT_H
