//
// Created by parallels on 9/6/16.
//

#include "componentmodel/r_componentbase.h"


// TODO: Move this somewhere else
#define ASYNC_CHANNEL "ipc://asyncresponsepublisher"

namespace riaps{

    void component_actor(zsock_t* pipe, void* args){
        ComponentBase* comp = (ComponentBase*)args;

        zsock_t* timerport = zsock_new_pull(comp->GetTimerChannel().c_str());
        assert(timerport);
        //std::cout << "Create async endpoint @" << comp->GetAsyncEndpointName() << std::endl;
        zsock_t* asyncport = zsock_new_sub(ASYNC_CHANNEL, comp->GetCompUuid().c_str());
        assert(asyncport);

        zpoller_t* poller = zpoller_new(pipe, NULL);
        assert(poller);

        zsock_signal (pipe, 0);

        int rc = zpoller_add(poller, asyncport);
        assert(rc==0);

        rc = zpoller_add(poller, timerport);
        assert(rc==0);

        // Init subscribers

        // TODO: Uncommented for debug, PUT IT BACK!
        //for (auto subscriberport : comp->GetSubscriberPorts()) {
        //    const zsock_t* socket = subscriberport->GetSocket();
        //    zpoller_add(poller, (zsock_t*)socket);
        //}

        bool terminated = false;
        bool firstrun = true;

        std::cout << "Component poller starts" << std::endl;

        while (!terminated) {
            void *which = zpoller_wait(poller, 1000);

            std::cout << "." << std::flush;

            if (firstrun) {
                firstrun = false;
                // Add and start publishers
                for (auto publisher : comp->GetConfig().component_ports.pubs) {
                    comp->AddPublisherPort(publisher);
                }

                // Add and start timers
                //for (auto timer : comp->GetConfig().periodic_timer_config) {
                //    comp->AddTimer(timer);
                //}

                // Add and start response ports
                //for (auto response : comp->GetConfig().responses_config) {
                //    auto responseport = ResponsePort::InitFromConfig(response);
                //    zpoller_add(poller, (zsock_t*)responseport->GetSocket());
                //    comp->AddResponsePort(responseport);
                //}

                // Add RequestPorts
                //for (auto requestconfig : comp->GetConfig().requests_config) {
                //    auto requestport = std::unique_ptr<RequestPort>(new RequestPort(requestconfig));
                //    comp->AddRequestPort(requestport);
                //}

                // Get subscriber details from discovery service
                //for (auto subscriber : comp->GetConfig().subscribers_config) {
                //    SubscriberPort::GetRemoteServiceAsync(subscriber, comp->GetCompUuid());
                //}
            }

            if (which == pipe) {
                zmsg_t *msg = zmsg_recv(which);
                if (!msg) {
                    std::cout << "No msg => interrupted" << std::endl;
                    break;
                }

                char *command = zmsg_popstr(msg);

                if (streq(command, "$TERM")) {
                    std::cout << "$TERM arrived in component" << std::endl;
                    terminated = true;
                }

                free(command);
                zmsg_destroy(&msg);
            }
            else if (which == timerport) {
                zmsg_t *msg = zmsg_recv(which);
                if (!msg) {
                    std::cout << "No msg => interrupted" << std::endl;
                    break;
                }

                char *param = zmsg_popstr(msg);

                if (param){
                    comp->OnTimerFired(param);
                    free (param);
                }
                zmsg_destroy(&msg);

            }
            // Message from async query
            else if (which == asyncport){
                std::cout<< "ASYNC ARRIVED, Create subscriber and connect" << std::endl;
                std::vector<service_details> services;
                zmsg_t *msg_response = zmsg_recv(which);

                if (!msg_response){
                    std::cout << "No msg => interrupted" << std::endl;
                    continue;
                }

                // The header must contain the UUID
                char* msg_header = zmsg_popstr(msg_response);

                // Todo, wrong message => log it
                if (strcmp(msg_header, comp->GetCompUuid().c_str())){
                    zmsg_destroy(&msg_response);
                    free(msg_header);
                    continue;
                }

                free(msg_header);

                std::vector<zmsg_t*> responseframes;
                extract_zmsg(msg_response, responseframes);

                for (auto it = responseframes.begin(); it!=responseframes.end(); it++) {
                    std::vector<std::string> params;
                    service_details current_service;
                    extract_params(*it, params);
                    params_to_service_details(params, current_service);
                    services.push_back(current_service);
                    zmsg_destroy(&(*it));
                }

                zmsg_destroy(&msg_response);

                if (!services.empty()) {
                    service_details target_service = services.front();
                    auto subscriberport = SubscriberPort::InitFromServiceDetails(target_service);
                    auto zmqport = subscriberport->GetSocket();
                    comp->AddSubscriberPort(subscriberport);

                    rc = zpoller_add(poller, (zsock_t*)zmqport);
                    assert(rc==0);
                }
            }
            // TODO: from one of the publishers?
            else if(which){
                // Message test with more than one field
                zmsg_t *msg = zmsg_recv(which);

                std::cout << zsock_type_str((zsock_t*)which) << std::endl;

                if (msg) {
                    char* messagetype = zmsg_popstr(msg);

                    comp->OnMessageArrived(std::string(messagetype), msg, (zsock_t*)which);

                    free(messagetype);

                    zmsg_destroy(&msg);
                }
            }
            else{
                // just poll timeout
            }
        }

        // Stop timers
        for (auto timer : comp->GetPeriodicTimers()){
            timer->stop();
        }

        zsock_destroy(&timerport);
        zsock_destroy(&asyncport);
        zpoller_destroy(&poller);
    };

    ComponentBase::ComponentBase(component_conf_j& config) {
        _configuration = config;




        //async uuid to the component instance
        _component_uuid = zuuid_new();

        get_servicebyname_poll_async("aaa", GetCompUuid());


        //zsock_component = zsock_new_rep("tcp://*:!");
        //assert(zsock_component);

        //async_address = "tcp://192.168.1.103:14352";
        //async_address = "";
        //_zsock_timer = zsock_new_pull(CHAN_TIMER_INPROC);
        //assert(_zsock_timer);

        //zpoller = zpoller_new(zsock_component, NULL);
        //assert(zpoller);

        _zactor_component = zactor_new(component_actor, this);

        // Create publishers
        //for (auto publisher : config.publishers_config) {
        //    AddPublisherPort(publisher);
        //}

        // Create subscribers
        //for (auto subscriber : config.subscribers_config) {
        //    AddSubscriberPort(subscriber);
        //}


    }

    //const zsock_t* ComponentBase::GetTimerPort() {
    //    return _zsock_timer;
    //}

    void ComponentBase::AddPublisherPort(publisher_conf& config) {
        std::unique_ptr<PublisherPort> newport(new PublisherPort(config));
        _publisherports.push_back(std::move(newport));
    }

    void ComponentBase::AddSubscriberPort(std::unique_ptr<SubscriberPort>& subscriberport) {
        //_subscriberports.push_back(std::move(subscriberport));
    }

    void ComponentBase::AddResponsePort(std::unique_ptr<ResponsePort>& responsePort) {
        //_responseports.push_back(std::move(responsePort));
    }

    void ComponentBase::AddRequestPort(std::unique_ptr<RequestPort>& requestPort) {
        //_requestports.push_back(std::move(requestPort));
    }

    void ComponentBase::AddTimer(periodic_timer_conf& config) {
        std::unique_ptr<CallBackTimer> newtimer(new CallBackTimer(config.timerid, GetTimerChannel()));
        newtimer->start(config.interval);
        //_periodic_timers.push_back(std::move(newtimer));
    }

    component_conf_j& ComponentBase::GetConfig() {
        return _configuration;
    }

    std::vector<PublisherPort*> ComponentBase::GetPublisherPorts() {

        std::vector<PublisherPort*> results;

        for (auto it=_publisherports.begin(); it!=_publisherports.end(); it++){
            results.push_back(it->get());
        }

        return results;
    }

    std::vector<RequestPort*> ComponentBase::GetRequestPorts() {

        std::vector<RequestPort*> results;

        //for (auto it=_requestports.begin(); it!=_requestports.end(); it++){
        //    results.push_back(it->get());
        //}

        return results;
    }

    std::vector<CallBackTimer*> ComponentBase::GetPeriodicTimers() {
        std::vector<CallBackTimer*> results;

        //for (auto it=_periodic_timers.begin(); it!=_periodic_timers.end(); it++){
        //    results.push_back(it->get());
        //}

        return results;
    }

    std::string ComponentBase::GetTimerChannel() {
        std::string prefix= "inproc://timer";
        return prefix + GetCompUuid();
    }

    std::string ComponentBase::GetCompUuid(){
        return std::string(zuuid_str(_component_uuid));
    }

    std::vector<SubscriberPort*> ComponentBase::GetSubscriberPorts() {

        std::vector<SubscriberPort*> results;

        //for (auto it=_subscriberports.begin(); it!=_subscriberports.end(); it++){
        //    results.push_back(it->get());
        //}

        return results;
    }

    ComponentBase::~ComponentBase() {


        zmsg_t* termmsg = zmsg_new();

        zmsg_addstr(termmsg,"$TERM");
        zactor_send(_zactor_component, &termmsg);

        zuuid_destroy(&_component_uuid);
        //zsock_destroy(&zsock_component);
        //zsock_destroy(&_zsock_timer);
        zactor_destroy(&_zactor_component);

    }

}