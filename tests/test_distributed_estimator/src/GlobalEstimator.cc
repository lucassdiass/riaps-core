//
// Created by istvan on 11/11/16.
//


#include <GlobalEstimator.h>

comp_globalestimator::comp_globalestimator(_component_conf_j &config, riaps::Actor &actor):ComponentBase(config, actor) {

}

void comp_globalestimator::OnMessageArrived(std::string messagetype, zmsg_t *msg_body, zsock_t *socket) {

}

void comp_globalestimator::OnTimerFired(std::string timerid) {

}

comp_globalestimator::~comp_globalestimator() {

}

riaps::ComponentBase* create_component(_component_conf_j& config, riaps::Actor& actor){
    return new comp_globalestimator(config, actor);
}

void destroy_component(riaps::ComponentBase* comp){
    delete comp;
}