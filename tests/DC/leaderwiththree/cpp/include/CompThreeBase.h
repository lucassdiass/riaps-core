//
// Auto-generated by edu.vanderbilt.riaps.generator.ComponenetGenerator.xtend
//

#ifndef RIAPS_CORE_COMPTHREE_H
#define RIAPS_CORE_COMPTHREE_H

#include "componentmodel/r_componentbase.h"

// Name of the ports from the model file
#define PORT_TIMER_CLOCK "clock"

namespace leaderwithtree {
  namespace components {

    class CompThreeBase : public riaps::ComponentBase {

    public:
      CompThreeBase(_component_conf &config, riaps::Actor &actor);

      virtual void OnClock(riaps::ports::PortBase *port) = 0;

      virtual ~CompThreeBase();

    protected:
      virtual void
      DispatchMessage(capnp::FlatArrayMessageReader *capnpreader,
                      riaps::ports::PortBase *port,
                      std::shared_ptr<riaps::MessageParams> params = nullptr);
      virtual void DispatchInsideMessage(zmsg_t *zmsg,
                                         riaps::ports::PortBase *port);
    };
  } // namespace components
} // namespace groupmsgtest
#endif // RIAPS_CORE_COMPTHREE_H
