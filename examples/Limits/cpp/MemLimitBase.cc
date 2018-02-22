//
// Auto-generated by edu.vanderbilt.riaps.generator.ComponenetGenerator.xtend
//
#include "include/MemLimitBase.h"

namespace limits {
   namespace components {
      
      MemLimitBase::MemLimitBase(_component_conf &config, riaps::Actor &actor) : ComponentBase(config, actor) {
         
      }
      
      void MemLimitBase::DispatchMessage(capnp::FlatArrayMessageReader* capnpreader, riaps::ports::PortBase *port,std::shared_ptr<riaps::MessageParams> params) {
         auto portName = port->GetPortName();
         if (portName == PORT_TIMER_TICKER) {
            OnTicker(port);
         }
         
      }
      
      void MemLimitBase::DispatchInsideMessage(zmsg_t* zmsg, riaps::ports::PortBase* port) {
         //empty the header
      }
      
      
      MemLimitBase::~MemLimitBase() {
         
      }
   }
}
