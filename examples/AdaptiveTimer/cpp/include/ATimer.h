//
// Auto-generated by edu.vanderbilt.riaps.generator.ComponenetGenerator.xtend
//
#ifndef RIAPS_FW_ATIMER_H
#define RIAPS_FW_ATIMER_H

#include "ATimerBase.h"
#include <spdlog/formatter.h>

namespace adaptivetimer {
   namespace components {
      
      class ATimer : public ATimerBase {
         
         public:
         
         ATimer(_component_conf &config, riaps::Actor &actor);
         
         virtual void OnClock(riaps::ports::PortBase *port);
         
         void OnGroupMessage(const riaps::groups::GroupId& groupId, capnp::FlatArrayMessageReader& capnpreader, riaps::ports::PortBase* port);

          void OnScheduledTimer(const uint64_t timerId);

         virtual ~ATimer();

      private:

          uint64_t _earlyWakeupOffset;
          uint64_t _avgDelay;

          bool _started;
          std::unordered_map<uint64_t, timespec> _timers;
         std::vector<std::string> _logs;
      };
   }
}

extern "C" riaps::ComponentBase* create_component(_component_conf&, riaps::Actor& actor);
extern "C" void destroy_component(riaps::ComponentBase*);


#endif //RIAPS_FW_ATIMER_H
