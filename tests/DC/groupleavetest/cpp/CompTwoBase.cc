//
// Auto-generated by edu.vanderbilt.riaps.generator.ComponenetGenerator.xtend
//
#include <CompTwoBase.h>

namespace groupmsgtest {
   namespace components {
      
      CompTwoBase::CompTwoBase(_component_conf &config, riaps::Actor &actor) : ComponentBase(config, actor) {
         
      }
      
      void CompTwoBase::DispatchMessage(capnp::FlatArrayMessageReader* capnpreader, riaps::ports::PortBase *port,std::shared_ptr<riaps::MessageParams> params) {
         auto portName = port->GetPortName();
         if (portName == PORT_TIMER_CLOCK) {
            OnClock(port);
         }
         
      }
      
      void CompTwoBase::DispatchInsideMessage(zmsg_t* zmsg, riaps::ports::PortBase* port) {
         //empty the header
      }
      
      
      CompTwoBase::~CompTwoBase() {
         
      }
   }
}
