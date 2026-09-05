"""Cross-title regression: the tool must not be specific to one game."""
import sys, tempfile, shutil, collections
from pathlib import Path
import rldcore as core, rldir as ir, disassembler as dis
CORP=[("GuardianPlace","E:/GuardianPlace/rld"),("hosisoraTP_01","E:/hosisoraTP_01/rld"),
("Yotsuiro","E:/Yotsuiro/rld"),("nyanCafe","E:/にゃんカフェマキアート/rld"),
("DemonBusters","E:/デーモンバスターズ/rld"),("galtool-ExHIBIT","E:/gal翻译工具2/ExHIBIT/ExHIBIT/rld"),
("GP-patch","E:/GuardianPlace/Nepgear2/rld")]
print(f"{'title':18}{'files':>6}{'keys':>5}{'decoded':>9}{'roundtrip':>10}{'cov':>6}{'msg':>7}{'name':>6}{'choice':>7}  names")
print("-"*95)
allok=True
for name,path in CORP:
    if not Path(path).is_dir(): continue
    work=Path(tempfile.mkdtemp())
    try:
        s=dis.Session(dis.collect_sources([path]),work,log=lambda *a:None)
        s.resolve_keys(); s.build_name_table()
        n=len(s.sources); rt=0; worst=1.0; tags=collections.Counter(); dec=0
        for doc in s.documents():
            dec+=1
            if core.apply_cipher(doc.plain,doc.key)==doc.raw: rt+=1
            c=ir.coverage(doc); worst=min(worst,c['byte_coverage'])
            ir.extract_texts(doc,s.name_table)
            for t in doc.texts: tags[t.tag]+=1
        ok = (dec==n and rt==dec and worst==1.0 and tags.get('msg',0)>0)
        allok &= ok
        sample=",".join(list(s.name_table.values())[:3])
        print(f"{name:18}{n:6}{len(s.groups):5}{dec:9}{rt:10}{worst:6.2f}"
              f"{tags.get('msg',0):7}{tags.get('name',0):6}{tags.get('choice',0):7}  "
              f"{len(s.name_table)}: {sample}{'' if ok else '   <-- FAIL'}")
    finally: shutil.rmtree(work,ignore_errors=True)
print("-"*95)
print("ALL TITLES PASS" if allok else "SOME TITLES FAILED")
sys.exit(0 if allok else 1)
