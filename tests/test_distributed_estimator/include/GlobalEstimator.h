//
// Created by istvan on 11/11/16.
//

#ifndef RIAPS_FW_GLOBALESTIMATOR_H
#define RIAPS_FW_GLOBALESTIMATOR_H

#include "componentmodel/r_componentbase.h"

class comp_globalestimator : public riaps::ComponentBase {

public:

    comp_globalestimator(_component_conf_j& config, riaps::Actor& actor);

    virtual void OnMessageArrived(std::string messagetype, zmsg_t* msg_body, zsock_t* socket);

    virtual void OnTimerFired(std::string timerid);

    virtual ~comp_globalestimator();

private:
    std::unique_ptr<std::uniform_real_distribution<double>> unif;
    std::default_random_engine                              re;
};

extern "C" riaps::ComponentBase* create_component(_component_conf_j&, riaps::Actor& actor);
extern "C" void destroy_component(riaps::ComponentBase*);


#endif //RIAPS_FW_GLOBALESTIMATOR_H
