import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Repository root: scripts -> up one.
const workspace=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const projects=["src","test"];
const runtimeExtensions=new Set([".log",".jsonl",".out",".err"]);
const secretShapes=[/ya29\.[A-Za-z0-9._~-]+/g,/AIza[0-9A-Za-z_-]{20,}/g,/Bearer\s+(?!\[REDACTED\])[A-Za-z0-9._~+\-/]+=*/g,/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,/\b(?:code|session_id|sessionid)=[A-Za-z0-9._~+\-/]{16,}/g];
const sourceRisks=[/structuredContent\s*:\s*(?:apiKey|accessToken|refreshToken|developerToken|clientSecret)/g,/return\s*\{[^}]{0,300}\b(?:apiKey|accessToken|refreshToken|developerToken|clientSecret)\s*[:,]/gs,/text\s*:\s*(?:e|error)(?:\?\.)?\.message/g,/content\s*:\s*\[[^\]]*stack/gs];
const findings=[];
function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){if(["node_modules",".secrets",".git",".cache"].includes(entry.name))continue;const file=path.join(dir,entry.name);if(entry.isDirectory())walk(file);else scan(file);}}
function scan(file){let text;try{text=fs.readFileSync(file,"utf8");}catch{return;}const ext=path.extname(file).toLowerCase();if(runtimeExtensions.has(ext)){secretShapes.forEach((pattern,index)=>{pattern.lastIndex=0;if(pattern.test(text))findings.push({type:`runtime_secret_shape_${index+1}`,file:path.relative(workspace,file)});});}if([".js",".mjs"].includes(ext)){sourceRisks.forEach((pattern,index)=>{pattern.lastIndex=0;if(pattern.test(text))findings.push({type:`source_exposure_risk_${index+1}`,file:path.relative(workspace,file)});});}}
for(const project of projects){const dir=path.join(workspace,project);if(fs.existsSync(dir))walk(dir);}
console.log(JSON.stringify({projects_scanned:projects.length,findings_count:findings.length,findings},null,2));
process.exitCode=findings.length?1:0;
