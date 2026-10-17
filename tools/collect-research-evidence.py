#!/usr/bin/env python3
import argparse,datetime,hashlib,json,platform,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument("--build",default="build");p.add_argument("--output",required=True);a=p.parse_args();root=Path(__file__).parents[1];build=root/a.build
tests=["test_research_ledger","test_research_mesh","test_science_validator_adapter","test_tunnel_dataplane"]
results=[]
for name in tests:
 r=subprocess.run([str(build/name)],cwd=root,text=True,capture_output=True,timeout=60)
 results.append({"name":name,"exit_code":r.returncode,"output_sha256":hashlib.sha256((r.stdout+r.stderr).encode()).hexdigest()})
sources=["src/modules/research_ledger.hpp","src/modules/research_mesh.hpp","src/modules/research_store.hpp","src/modules/science_validator_adapter.hpp","src/modules/node_module.hpp","src/modules/node_module.cpp"]
e={"schema":"pqvpn-research-evidence-v1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"platform":platform.platform(),"tests":results,"sources":{s:hashlib.sha256((root/s).read_bytes()).hexdigest() for s in sources},"all_passed":all(x["exit_code"]==0 for x in results),"independent_audit":False}
out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(e,indent=2)+"\n");raise SystemExit(0 if e["all_passed"] else 1)
