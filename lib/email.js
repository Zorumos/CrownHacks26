// Public sender identity is fixed; its Google App Password stays server-side.
export const SENDER_EMAIL='Cyber0neNorthCarolinaUSA@gmail.com';
export function emailBase(){try{const u=new URL(process.env.APP_URL||'http://localhost:3000');if(u.username||u.password||u.pathname!=='/'||u.search||u.hash)return null;if(u.protocol!=='https:'&&!(u.protocol==='http:'&&!process.env.VERCEL&&['localhost','127.0.0.1'].includes(u.hostname)))return null;if(process.env.VERCEL&&!process.env.APP_URL)return null;return u.origin;}catch{return null;}}
const appPassword=()=>String(process.env.GMAIL_APP_PASSWORD||'').replace(/\s/g,'');
export const emailReady=()=>appPassword().length===16&&!!emailBase();
// Optional factory is an internal test seam, never accepted from an HTTP body.
export async function sendEmail(mail,createTransport){
 if(!emailReady())throw Error('Gmail recovery is not configured');
 if(!createTransport){const {default:nodemailer}=await import('nodemailer');createTransport=nodemailer.createTransport;}
 const transport=createTransport({host:'smtp.gmail.com',port:465,secure:true,pool:true,maxConnections:1,maxMessages:1,auth:{user:SENDER_EMAIL,pass:appPassword()},tls:{minVersion:'TLSv1.2',rejectUnauthorized:true},connectionTimeout:4000,greetingTimeout:4000,socketTimeout:6000,disableFileAccess:true,disableUrlAccess:true,logger:false,debug:false});
 let timer;
 try{
  const result=await Promise.race([transport.sendMail({from:{name:'Cyber One',address:SENDER_EMAIL},to:mail.to,subject:mail.subject,text:mail.text,messageId:`<cyberone-${mail.key}@gmail.com>`,disableFileAccess:true,disableUrlAccess:true}),new Promise((_,reject)=>{timer=setTimeout(()=>{transport.close({force:true});reject(Error('Gmail delivery timed out'));},8000);})]);
  if(!Array.isArray(result.accepted)||!result.accepted.length||(result.rejected?.length))throw Error('Gmail did not accept the recipient');
 }catch{throw Error('Gmail could not accept this message; check account settings and delivery limits');}
 finally{clearTimeout(timer);transport.close({force:true});}
}
