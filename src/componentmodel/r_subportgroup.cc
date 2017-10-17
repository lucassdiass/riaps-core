//
// Created by istvan on 10/17/17.
//

#include <componentmodel/r_subportgroup.h>

namespace riaps{
    namespace ports{

        GroupSubscriberPort::GroupSubscriberPort(const _component_port_sub &config)
            : _groupPortConfig(config), SubscriberPortBase(&_groupPortConfig) {
        }

        GroupSubscriberPort* GroupSubscriberPort::AsGroupSubscriberPort() {
            return this;
        }

        GroupSubscriberPort::~GroupSubscriberPort() {

        }

    }
}