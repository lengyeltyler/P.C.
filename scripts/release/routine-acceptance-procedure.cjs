"use strict";
const OWNER_INSTRUCTIONS="Complete this sequence without stopping to report between scan and approval: scan request 1, compare both fingerprints, review the harmless local action, and approve with the normal user-presence check. After the phone reports approval sent and Desktop verifies success, scan request 2, compare and review it, then tap Deny. Stop immediately on any mismatch or unexpected state. Never approve an unexpected action.";
function createAcceptanceProcedure({baseline,now=()=>Math.floor(Date.now()/1000)}) {
  if(baseline?.verdict!=="PHYSICAL ACCEPTANCE BASELINE: PASS"||baseline.errors?.length!==0||!Number.isSafeInteger(baseline.verifiedAt)||now()-baseline.verifiedAt>30||now()<baseline.verifiedAt) throw new Error("ACCEPTANCE_BASELINE_REQUIRED");
  let phase="ready",active=null,stopped=false,generating=false;
  return Object.freeze({
    instructions:OWNER_INSTRUCTIONS,
    async generateRequest(beginRequest) {
      // Own the call that creates the timed request; never admit a request that
      // was generated before these contamination checks. The production begin
      // API additionally checks the durable host for active/unknown requests.
      if(stopped||active||generating||!["ready","first_succeeded"].includes(phase)||typeof beginRequest!=="function") {
        stopped=true;throw new Error("ACCEPTANCE_STOP_AND_DEBUG");
      }
      if(phase==="ready"&&(now()-baseline.verifiedAt>30||now()<baseline.verifiedAt)) {
        stopped=true;throw new Error("ACCEPTANCE_BASELINE_STALE");
      }
      generating=true;
      try {
        const request=await beginRequest();
        if(stopped) throw new Error("ACCEPTANCE_STOP_AND_DEBUG");
        if(!request?.requestId||!request.qrPayload||!Number.isSafeInteger(Number(request.expiresAt))||Number(request.expiresAt)-now()<110) {
          throw new Error("ACCEPTANCE_REQUEST_SETUP_CONTAMINATED");
        }
        active=request.requestId;
        return Object.freeze({request,instruction:OWNER_INSTRUCTIONS,decision:phase==="ready"?"approve":"reject"});
      } catch(error) {stopped=true;throw error;}
      finally {generating=false;}
    },
    observe(result) {
      if(stopped||!active||result?.requestId!==active) {stopped=true;throw new Error("ACCEPTANCE_UNKNOWN_REQUEST");}
      if(phase==="ready"&&result.state===9) {phase="first_succeeded";active=null;return "CONTINUE";}
      if(phase==="first_succeeded"&&result.state===20&&result.terminalReason==="rejected") {phase="complete";active=null;return "COMPLETE";}
      if([1,2,3,4,5,6,7,8].includes(result.state)) return "OBSERVE_WITHOUT_OWNER_PAUSE";
      stopped=true;throw new Error("ACCEPTANCE_STOP_AND_DEBUG");
    },
    interrupt() {stopped=true;return "RESET_TRANSIENT_STATE_ONLY_AFTER_PROVING_NO_SUBMISSION; DISCARD_THIS_SCENARIO";},
    status:()=>Object.freeze({phase,active,stopped,generating})
  });
}
module.exports={createAcceptanceProcedure,OWNER_INSTRUCTIONS};
