"use strict";
const HEADER_SIZE=36;
const MIN_ITERATIONS=100000;
const MAX_ITERATIONS=2000000;
const encoder=new TextEncoder();
const decoder=new TextDecoder();
const form=document.getElementById("unlock-form");
const input=document.getElementById("access-code");
const button=document.getElementById("unlock-button");
const error=document.getElementById("error");
const gate=document.getElementById("gate");
const frame=document.getElementById("archive-frame");

function bytesEqualAscii(bytes,text){
  if(bytes.length!==text.length)return false;
  for(let index=0;index<text.length;index+=1){
    if(bytes[index]!==text.charCodeAt(index))return false;
  }
  return true;
}

async function deriveKey(code,salt,iterations){
  const material=await crypto.subtle.importKey(
    "raw",
    encoder.encode(code),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",hash:"SHA-256",salt,iterations},
    material,
    {name:"AES-GCM",length:256},
    false,
    ["decrypt"]
  );
}

async function openArchive(code){
  const response=await fetch("./sealed/archive-v1.bin",{cache:"no-store"});
  if(!response.ok)throw new Error("Archive unavailable");
  const bytes=new Uint8Array(await response.arrayBuffer());
  if(bytes.length<=HEADER_SIZE||!bytesEqualAscii(bytes.slice(0,4),"AFV1")){
    throw new Error("Invalid archive");
  }
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  const iterations=view.getUint32(4,false);
  if(iterations<MIN_ITERATIONS||iterations>MAX_ITERATIONS){
    throw new Error("Unsupported archive");
  }
  const header=bytes.slice(0,HEADER_SIZE);
  const salt=bytes.slice(8,24);
  const iv=bytes.slice(24,36);
  const ciphertext=bytes.slice(HEADER_SIZE);
  const key=await deriveKey(code,salt,iterations);
  const plaintext=await crypto.subtle.decrypt(
    {name:"AES-GCM",iv,additionalData:header,tagLength:128},
    key,
    ciphertext
  );
  const html=decoder.decode(plaintext);
  if(!html.startsWith("<!doctype html>")||!html.includes("<main")){
    throw new Error("Invalid plaintext");
  }
  frame.srcdoc=html;
  gate.hidden=true;
  frame.hidden=false;
  document.body.classList.add("unlocked");
  document.title="Archivo familiar privado";
}

form.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const code=input.value.trim();
  error.hidden=true;
  if(code.length<20||code.length>128){
    error.hidden=false;
    input.focus();
    return;
  }
  button.disabled=true;
  button.textContent="Descifrando…";
  try{
    await openArchive(code);
    input.value="";
  }catch{
    error.hidden=false;
    input.select();
    button.disabled=false;
    button.textContent="Abrir el archivo";
  }
});
