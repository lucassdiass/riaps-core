//
// Created by istvan on 9/30/16.
//

#include <componentmodel/ports/r_queryport.h>
#include <fmt/format.h>

namespace riaps {
    namespace ports {

        QueryPort::QueryPort(const _component_port_qry &config, const ComponentBase *component)
                : PortBase(PortTypes::Query,
                           (component_port_config*)(&config),
                           component),
                  _capnpReader(capnp::FlatArrayMessageReader(nullptr)) {
            _port_socket = zsock_new(ZMQ_DEALER);
            _socketId = zuuid_new();

            //auto i = zsock_rcvtimeo (_port_socket);

            int timeout = 500;//msec
            int lingerValue = 0;
            int connectTimeout = 1000; //msec
            zmq_setsockopt(_port_socket, ZMQ_SNDTIMEO, &timeout , sizeof(int));
            zmq_setsockopt(_port_socket, ZMQ_LINGER, &lingerValue, sizeof(int));
            zsock_set_identity(_port_socket, zuuid_str(_socketId));

            //i = zsock_rcvtimeo (_port_socket);

            _isConnected = false;
        }



        void QueryPort::Init() {

            const _component_port_qry* current_config = GetConfig();

            auto results =
                    subscribeToService(GetParentComponent()->GetActor()->GetApplicationName(),
                                       GetParentComponent()->GetConfig().component_name,
                                       GetParentComponent()->GetActor()->GetActorName(),
                                       riaps::discovery::Kind::QRY,
                                       (current_config->isLocal?riaps::discovery::Scope::LOCAL:riaps::discovery::Scope::GLOBAL),
                                       current_config->portName, // Subscriber name
                                       current_config->messageType);

            for (auto result : results) {
                std::string endpoint = fmt::format("tcp://{0}:{1}", result.host_name, result.port);
                //std::string endpoint = "tcp://" + result.host_name + ":" + std::to_string(result.port);
                ConnectToResponse(endpoint);
            }
        }

        bool QueryPort::ConnectToResponse(const std::string &ansEndpoint) {
            int rc = zsock_connect(_port_socket, "%s", ansEndpoint.c_str());

            if (rc != 0) {
                _logger->error("Queryport {} couldn't connect to {}", GetConfig()->portName, ansEndpoint);
                return false;
            }

            _isConnected = true;
            _logger->info("Queryport connected to: {}", ansEndpoint);
            return true;
        }

        const _component_port_qry* QueryPort::GetConfig() const{
            return (_component_port_qry*)GetPortBaseConfig();
        }

        QueryPort* QueryPort::AsQueryPort() {
            return this;
        }

//        bool QueryPort::RecvQuery(std::shared_ptr<capnp::FlatArrayMessageReader>& messageReader,
//                                  std::shared_ptr<riaps::MessageParams>& params) {
//            /**
//             * |RequestId|Message|Timestamp|
//             */
//
//            char* cRequestId = nullptr;
//            zframe_t *bodyFrame = nullptr, *timestampFrame = nullptr;
//            if (zsock_recv(_port_socket, "sff", &cRequestId, &bodyFrame, &timestampFrame)==0){
//                std::string socketId = zuuid_str(_socketId);
//                params.reset(new riaps::MessageParams(socketId, &cRequestId, &timestampFrame));
//            } else {
//                _logger->error("Wrong incoming message format on port: {}", GetPortName());
//            }
//
//            return false;
//        }


        bool QueryPort::SendQuery(capnp::MallocMessageBuilder &message,std::string& requestId, bool addTimestamp) const {
            if (_port_socket == nullptr || !_isConnected){
                return false;
            }

            zframe_t* userFrame;
            userFrame << message;

            zframe_t* tsFrame = nullptr;
            if (addTimestamp){
                int64_t ztimeStamp = zclock_time();
                tsFrame = zframe_new(&ztimeStamp, sizeof(ztimeStamp));
            } else{
                tsFrame = zframe_new_empty();
            }


            // Create the timestamp
            //capnp::MallocMessageBuilder tsBuilder;
            //auto msgTimestamp = tsBuilder.initRoot<riaps::distrcoord::RiapsTimestamp>();

            // Build the timestamp
            //msgTimestamp.setValue(zclock_mono());
            //zmsg_t* zmsgTimestamp;
            //zmsgTimestamp << tsBuilder;

            // Create expiration time
            //capnp::MallocMessageBuilder expBuilder;
            //auto msgExpire = expBuilder.initRoot<riaps::distrcoord::RiapsTimestamp>();
            //msgExpire.setValue(expiration);
            //zmsg_t* zmsgExpiration;
            //zmsgExpiration << expBuilder;

            // Generate uniqueId
            std::string msgId;
            {
                auto id = zuuid_new();
                msgId.assign(zuuid_str(id));
                zuuid_destroy(&id);
            }

            int rc = zsock_send(const_cast<zsock_t*>(GetSocket()),
                                "sff",
                                msgId.c_str() ,
                                userFrame,
                                tsFrame
                                )
            ;

            zframe_destroy(&userFrame);
            zframe_destroy(&tsFrame);
            if (rc == 0) {
                requestId = msgId;
                return true;
            }
            return false;
        }

        QueryPort::~QueryPort() noexcept {
            zuuid_destroy(&_socketId);
        }


    }
}