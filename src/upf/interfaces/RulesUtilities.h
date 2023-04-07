#ifndef __RULESUTILITIES_H__
#define __RULESUTILITIES_H__

#include <memory>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>

class ForwardingActionRules;
class PacketDetectionRules;

// TODO navarrothiago check if this class can be called by AbstractFactory.
class RulesUtilities
{
public:
  RulesUtilities(/* args */) {}
  virtual ~RulesUtilities() {}
  virtual void copyFAR(pfcp_far_t_ *pFarDestination, ForwardingActionRules *pFarSource) = 0;
  virtual std::shared_ptr<ForwardingActionRules> createFAR(pfcp_far_t_ *pFarSource) = 0;
  virtual void copyPDR(pfcp_pdr_t_ *pPdrDestination, PacketDetectionRules *pPdrSource) = 0;
  virtual std::shared_ptr<PacketDetectionRules> createPDR(pfcp_pdr_t_ *pPdrSource) = 0;
};

#endif // __RULESUTILITIES_H__
