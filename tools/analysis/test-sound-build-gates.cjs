const fs=require('fs'),vm=require('vm'),path=require('path');
const src=fs.readFileSync(path.join(__dirname,'../../module/patch.js'),'utf8');
const defs=['FP_KNOWN','FP_5364_SOUND'].map(n=>src.match(new RegExp('const '+n+' = (.*);'))[0]).join('\n');
const body=src.slice(src.indexOf('function v2Fingerprints()'),src.indexOf('// --- mapped ELF helpers'));
const ctx={};vm.createContext(ctx);vm.runInContext(defs+'\n'+body+'\nthis.tables={old:FP_KNOWN,newer:FP_5364_SOUND};',ctx);
function run(id,table,corrupt){let reads=[];ctx.V2={status:{buildId:id,fingerprints:{}},mod:{findExportByName:n=>n}};ctx.fpHash=(s,len)=>{const row=Object.values(table).flat().find(r=>r[0]===s);if(!row||row[1]!==len)throw Error('incorrect length '+s);reads.push(s);return corrupt===s?'00000000':row[2][0];};return ctx.v2Fingerprints();}
const newer=Object.assign({},ctx.tables.old,ctx.tables.newer);
if(Object.values(run('691c2ee61f7a149bf3851dd64788b3479078670f',newer)).some(Boolean))throw Error('5364 rejected');
if(Object.values(run('71b29157d3c140d74ad13563013ffb300dda63ac',ctx.tables.old)).some(Boolean))throw Error('5339 rejected');
const bad=run('691c2ee61f7a149bf3851dd64788b3479078670f',newer,newer.snd[0][0]);if(!bad.snd)throw Error('mutation accepted');

const badShared=run('691c2ee61f7a149bf3851dd64788b3479078670f',newer,newer.snd[2][0]);if(!badShared.snd||!badShared.strm)throw Error('shared mutation accepted');

console.log('PASS: mocked 5339/5364 table selection and altered sound/shared fingerprint rejection. Runtime compatibility not tested.');
