"use strict";

const http=require("node:http");
const {createECDH,randomBytes}=require("node:crypto");
require("tsx/cjs");
const deviceRequest=require("../../../phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const transport=require("../../../phil-device-sdk/src/routineAuthorizationTransportV1.ts");

function fail(code){const error=new Error(code);error.code=code;throw error;}
function headers(value){const out=Object.create(null);for(const [key,item] of Object.entries(value||{})){if(Array.isArray(item)||Object.hasOwn(out,key.toLowerCase()))fail("SEPOLIA_MINT_HTTP_HEADERS_INVALID");out[key.toLowerCase()]=String(item);}return out;}
function response(status,headersValue={},body=Buffer.alloc(0)){return Object.freeze({status,headers:Object.freeze({...headersValue}),body:Buffer.from(body)});}
function destroy(session){if(Buffer.isBuffer(session.privateKey))session.privateKey.fill(0);session.cipher?.destroy();session.cipher=null;}

function createSepoliaMintDeviceAuthorizationHost(options){
  if(!options||Object.keys(options).sort().join(",")!=="ceremonyStore,enrollment,ipv4,now,onApproved,requestFactory")fail("SEPOLIA_MINT_HOST_OPTIONS_INVALID");
  if(typeof options.requestFactory!=="function"||typeof options.onApproved!=="function"||typeof options.now!=="function")fail("SEPOLIA_MINT_HOST_DEPENDENCY_INVALID");
  const sessions=new Map();let listener=null;
  async function begin(input={}){
    if(Object.keys(input).some((key)=>key!=="port"))fail("SEPOLIA_MINT_HOST_BEGIN_OPTIONS_INVALID");
    if([...sessions.values()].some((session)=>!["completed","cancelled","expired","failed"].includes(session.state)))fail("SEPOLIA_MINT_HOST_ACTIVE_SESSION_EXISTS");
    const now=BigInt(options.now()),sessionId=`0x${randomBytes(32).toString("hex")}`,approvalNonce=`0x${randomBytes(32).toString("hex")}`;
    const produced=await options.requestFactory({sessionId,approvalNonce,now:now.toString()});
    const request=deviceRequest.validatePhilSepoliaMintDeviceRequestV1(produced?.request||produced,options.enrollment),context=produced?.request?produced.context:{};
    if(request.sessionId!==sessionId||request.approvalNonce!==approvalNonce||BigInt(request.approvalExpiresAt)<=now)fail("SEPOLIA_MINT_HOST_REQUEST_BINDING_INVALID");
    const port=input.port||listener?.address()?.port;if(!Number.isInteger(port)||port<1||port>65535)fail("SEPOLIA_MINT_HOST_PORT_INVALID");
    await options.ceremonyStore.saveRequest({requestId:request.requestId,requestJson:JSON.stringify(request),contextJson:JSON.stringify(context),createdAt:now.toString(),expiresAt:request.approvalExpiresAt});
    const ecdh=createECDH("prime256v1");ecdh.generateKeys();
    const bootstrap=Object.freeze({sessionId,ipv4:options.ipv4,port,desktopPublicKeyX963:`0x${ecdh.getPublicKey(undefined,"uncompressed").toString("hex")}`,requestId:request.requestId,expiresAt:request.approvalExpiresAt});
    sessions.set(request.requestId,{request,context,bootstrap,privateKey:Buffer.from(ecdh.getPrivateKey()),cipher:null,state:"waiting",fingerprint:null});
    return Object.freeze({requestId:request.requestId,qrPayload:transport.encodePhilRoutineTransportBootstrapV1(bootstrap),expiresAt:request.approvalExpiresAt,status:"waiting",presentation:request.humanPresentation});
  }
  function httpBody(input,session,type){const h=headers(input.headers),body=Buffer.from(input.body||[]);if(input.method!=="POST"||h["content-type"]!==type||h.host!==`${session.bootstrap.ipv4}:${session.bootstrap.port}`||h["content-length"]!==String(body.length)||h["cache-control"]!=="no-store"||Object.hasOwn(h,"content-encoding")||Object.hasOwn(h,"transfer-encoding")||body.length>transport.PHIL_ROUTINE_TRANSPORT_V1.maximumHttpBodyBytes)fail("SEPOLIA_MINT_HTTP_INVALID");return body;}
  async function dispatchHttp(input){
    const session=sessions.get(String(input?.requestId||"").toLowerCase());if(!session)return response(404);
    if(BigInt(options.now())>=BigInt(session.request.approvalExpiresAt)){session.state="expired";destroy(session);await options.ceremonyStore.markTerminal(session.request.requestId,"expired");return response(410);}
    try{
      if(input.path===transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath){
        if(session.state!=="waiting")fail("SEPOLIA_MINT_BEGIN_REPLAY");const beginRequest=transport.parsePhilRoutineTransportBeginJsonV1(httpBody(input,session,"application/json"));
        if(beginRequest.sessionId!==session.bootstrap.sessionId||beginRequest.requestId!==session.bootstrap.requestId)fail("SEPOLIA_MINT_BEGIN_BINDING_INVALID");
        const transcriptHash=transport.derivePhilRoutineTransportTranscriptHashV1({bootstrap:session.bootstrap,iphonePublicKeyX963:beginRequest.iphonePublicKey});
        const key=transport.derivePhilRoutineTransportKeyV1({privateKey:session.privateKey,peerPublicKeyX963:beginRequest.iphonePublicKey,transcriptHash});session.privateKey.fill(0);session.cipher=new transport.PhilRoutineTransportCipherV1({key});session.state="reviewing";session.fingerprint=transport.formatPhilRoutineTransportFingerprintV1(transcriptHash);
        const aad=transport.derivePhilRoutineTransportAadV1({direction:"request",sessionId:session.bootstrap.sessionId,requestId:session.bootstrap.requestId});const encrypted=session.cipher.encrypt({plaintext:JSON.stringify(session.request),aad});
        return response(200,{"content-type":"application/octet-stream","content-length":String(encrypted.length),"cache-control":"no-store",connection:"close"},encrypted);
      }
      if(input.path===transport.PHIL_ROUTINE_TRANSPORT_V1.completePath){
        if(session.state!=="reviewing"||!session.cipher)fail("SEPOLIA_MINT_COMPLETE_OUT_OF_ORDER");const body=httpBody(input,session,"application/octet-stream");const aad=transport.derivePhilRoutineTransportAadV1({direction:"response",sessionId:session.bootstrap.sessionId,requestId:session.bootstrap.requestId});const plaintext=session.cipher.decrypt({frame:body,aad});
        const parsed=deviceRequest.parsePhilSepoliaMintDeviceResponseJsonV1({request:session.request,enrollment:options.enrollment,json:plaintext});
        await options.ceremonyStore.saveResponse(session.request.requestId,JSON.stringify(parsed));session.state="approved";destroy(session);
        const outcome=await options.onApproved({request:session.request,response:parsed,context:session.context});await options.ceremonyStore.markCompleted(session.request.requestId,outcome);session.state="completed";
        return response(204,{"content-length":"0","cache-control":"no-store",connection:"close"});
      }
      return response(404);
    }catch(error){if(session.state!=="approved") {session.state="failed";destroy(session);}return response(String(error?.code||"").includes("REPLAY")||String(error?.code||"").includes("OUT_OF_ORDER")?409:400,{"content-length":"0","cache-control":"no-store",connection:"close"});}
  }
  async function restoreApproved(){const outcomes=[];for(const id of options.ceremonyStore.list()){const record=options.ceremonyStore.load(id);if(record.state!=="approved")continue;const request=JSON.parse(record.requestJson),responseValue=deviceRequest.parsePhilSepoliaMintDeviceResponseJsonV1({request,enrollment:options.enrollment,json:record.responseJson});const outcome=await options.onApproved({request,response:responseValue,context:JSON.parse(record.contextJson)});await options.ceremonyStore.markCompleted(id,outcome);outcomes.push(Object.freeze({requestId:id,outcome}));}return Object.freeze(outcomes);}
  function status(id){const session=sessions.get(String(id).toLowerCase()),record=options.ceremonyStore.load(id);return Object.freeze({requestId:record.requestId,state:session?.state||record.state,comparisonFingerprint:session?.fingerprint||null,expiresAt:record.expiresAt,completion:record.completion});}
  async function cancel(id){const session=sessions.get(String(id).toLowerCase());if(session)destroy(session);await options.ceremonyStore.markTerminal(id,"cancelled");if(session)session.state="cancelled";return "cancelled";}
  async function startListener(){if(listener)fail("SEPOLIA_MINT_LISTENER_ACTIVE");listener=http.createServer(async(req,res)=>{const chunks=[];for await(const chunk of req){chunks.push(chunk);}const body=Buffer.concat(chunks);let id=null;try{id=req.url===transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath?transport.parsePhilRoutineTransportBeginJsonV1(body).requestId:[...sessions.values()].find((item)=>item.state==="reviewing")?.request.requestId;}catch{}const result=await dispatchHttp({requestId:id,method:req.method,path:req.url,headers:req.headers,body});res.writeHead(result.status,result.headers);res.end(result.body);});await new Promise((resolve,reject)=>{listener.once("error",reject);listener.listen({host:options.ipv4,port:0,exclusive:true},resolve);});return Object.freeze({ipv4:options.ipv4,port:listener.address().port});}
  async function stopListener(){if(!listener)return;const current=listener;listener=null;await new Promise((resolve,reject)=>current.close((error)=>error?reject(error):resolve()));}
  return Object.freeze({begin,dispatchHttp,restoreApproved,getStatus:status,cancel,startListener,stopListener});
}
module.exports={createSepoliaMintDeviceAuthorizationHost};
