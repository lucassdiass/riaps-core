//
// Auto-generated by edu.vanderbilt.riaps.generator.ComponenetGenerator.xtend
//
#include <TscaGpioBase.h>

namespace tsyncgpio {
   namespace components {
      
      TscaGpioBase::TscaGpioBase(_component_conf &config, riaps::Actor &actor) : ComponentBase(config, actor) {
         
      }
      
      void TscaGpioBase::DispatchMessage(capnp::FlatArrayMessageReader* capnpreader, riaps::ports::PortBase *port,std::shared_ptr<riaps::MessageParams> params) {
         auto portName = port->GetPortName();
         if (portName == PORT_TIMER_CLOCK) {
            OnClock(port);
         }
         
      }
      
      void TscaGpioBase::DispatchInsideMessage(zmsg_t* zmsg, riaps::ports::PortBase* port) {
         //empty the header
      }
      
      
      TscaGpioBase::~TscaGpioBase() {
         
      }
   }
}