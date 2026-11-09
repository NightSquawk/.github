#!/usr/bin/env python3
"""Read-only public repository baseline audit; no credentials or alert payloads emitted."""
import argparse, base64, concurrent.futures, datetime, json, re, subprocess
from pathlib import Path
from urllib.parse import quote

def api(path,paginate=False):
    args=['gh','api',path]
    if paginate:args+=['--paginate','--slurp']
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=60)
    except subprocess.TimeoutExpired:
        return {'unavailable':'timeout'}
    except OSError:
        return {'unavailable':'client-unavailable'}
    if p.returncode:
        match=re.search(r'HTTP (\d+)',p.stderr)
        return {'unavailable':match.group(1) if match else 'request-failed'}
    try:value=json.loads(p.stdout)
    except json.JSONDecodeError:return {'unavailable':'invalid-response'}
    return [v for page in value for v in page] if paginate and isinstance(value,list) else value

def audit(repo):
    name=repo['full_name'];branch=repo['default_branch'];root='repos/'+name
    result={'repository':name,'default_branch':branch,'drift':[],'unknown':[]}
    rules=api(root+'/rules/branches/'+quote(branch,safe=''))
    if isinstance(rules,list):
        types={r['type'] for r in rules}
        for required in ['deletion','non_fast_forward','pull_request']:
            if required not in types:result['drift'].append('missing-default-rule:'+required)
        if not any(r.get('type')=='pull_request' and r.get('parameters',{}).get('required_review_thread_resolution') for r in rules):
            result['drift'].append('unresolved-review-threads-permitted')
    else:result['unknown'].append('effective-branch-rules:'+rules['unavailable'])
    sets=api(root+'/rulesets?includes_parents=true&per_page=100',True)
    if isinstance(sets,list):
        tag_sets=[s for s in sets if s.get('target')=='tag' and s.get('enforcement')=='active']
        protected=False
        for ruleset in tag_sets:
            detail=api(root+'/rulesets/'+str(ruleset['id']))
            if 'unavailable' in detail:
                result['unknown'].append('tag-ruleset:'+detail['unavailable']);continue
            included=detail.get('conditions',{}).get('ref_name',{}).get('include',[])
            excluded=detail.get('conditions',{}).get('ref_name',{}).get('exclude',[])
            types={r['type'] for r in detail.get('rules',[])}
            if 'refs/tags/v*' in included and not excluded and {'update','deletion'}<=types:protected=True
        if not protected:result['drift'].append('missing-version-tag-protection')
    else:result['unknown'].append('tag-rulesets:'+sets['unavailable'])
    tree=api(root+'/git/trees/'+quote(branch,safe='')+'?recursive=1')
    if tree.get('truncated') or 'unavailable' in tree:
        result['unknown'].append('workflow-tree-unavailable-or-truncated')
    else:
        for entry in tree.get('tree',[]):
            path=entry['path']
            if entry.get('type')!='blob' or not path.startswith('.github/workflows/') or not path.endswith(('.yml','.yaml')):continue
            blob=api(root+'/git/blobs/'+entry['sha'])
            if 'unavailable' in blob:
                result['unknown'].append('workflow-read:'+path);continue
            body=base64.b64decode(blob.get('content','')).decode()
            for match in re.finditer(r'(?m)^\s*-?\s*uses:\s*[\'\"]?([^\s\'\"#]+)',body):
                action=match[1]
                if action.startswith(('./','docker://')):continue
                if not re.search(r'@[0-9a-f]{40}$',action):result['drift'].append('unpinned-workflow-reference:'+path)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--owners',nargs='+',default=['NightSquawk','Kvrnn'])
    p.add_argument('--output',default='public-repo-drift.json')
    args=p.parse_args();inventory=[];errors=[]
    for owner in args.owners:
        data=api('users/'+owner+'/repos?type=owner&per_page=100',True)
        if not isinstance(data,list):errors.append(owner+':'+data['unavailable']);continue
        inventory.extend(r for r in data if not r.get('private') and not r.get('archived') and r['owner']['login'].lower()==owner.lower())
    def guarded_audit(repo):
        try:return audit(repo)
        except Exception:
            return {'repository':repo['full_name'],'default_branch':repo['default_branch'],'drift':[],'unknown':['audit-error']}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(guarded_audit,inventory))
    report={'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Active public repositories; default-branch rules, version-tag rules and workflow SHA references only. Security feature/admin settings need an administrator audit.','inventory_errors':errors,'repositories':results}
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    for r in results:print(r['repository']+': '+str(len(r['drift']))+' drift, '+str(len(r['unknown']))+' unknown')
    failed=bool(errors or any(r['drift'] or r['unknown'] for r in results))
    print('Baseline audit '+('requires attention' if failed else 'passed')+'; no settings were changed.')
    return int(failed)

if __name__=='__main__':raise SystemExit(main())
