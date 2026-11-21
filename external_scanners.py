#!/usr/bin/env python3
"""Optional adapters for Gitleaks, Semgrep and OSV-Scanner.
Only runs scanners against the configured local training project. Secret values are never copied into findings.
"""
from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT / 'training-project'
REPORT = ROOT / 'security-report'


def run_json(name, command, timeout=180):
    binary = shutil.which(command[0])
    if not binary:
        return [], {'available': False, 'status': 'not_installed', 'message': f'{command[0]} не найден в PATH'}
    command[0] = binary
    try:
        p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        if p.returncode not in (0, 1):
            return [], {'available': True, 'status': 'error', 'message': (p.stderr or p.stdout)[-1200:]}
        try:
            data = json.loads(p.stdout or '[]')
        except json.JSONDecodeError:
            return [], {'available': True, 'status': 'error', 'message': 'Анализатор вернул некорректный JSON: '+(p.stderr or '')[-500:]}
        return data, {'available': True, 'status': 'completed', 'exitCode': p.returncode}
    except subprocess.TimeoutExpired:
        return [], {'available': True, 'status': 'timeout', 'message': f'Превышено время ожидания {timeout} секунд'}
    except Exception as e:
        return [], {'available': True, 'status': 'error', 'message': str(e)}


def relpath(value):
    try:
        p = Path(value)
        if p.is_absolute(): return p.resolve().relative_to(PROJECT.resolve()).as_posix()
        s = p.as_posix()
        prefix = 'training-project/'
        return s[len(prefix):] if s.startswith(prefix) else s
    except Exception:
        return str(value or 'unknown')


def gitleaks():
    with tempfile.TemporaryDirectory(prefix='cg-gitleaks-') as td:
        out = str(Path(td) / 'gitleaks.json')
        raw, status = run_json('gitleaks', ['gitleaks','dir',str(PROJECT),'--report-format','json','--report-path',out,'--redact=100'])
        if status['status'] == 'completed':
            try: raw = json.loads(Path(out).read_text(encoding='utf-8')) if Path(out).exists() else []
            except Exception: raw=[]
    findings=[]
    for x in raw if isinstance(raw,list) else []:
        findings.append({'category':'SECRET','source':'Gitleaks','path':relpath(x.get('File')),'class':x.get('RuleID') or 'secret-detected','line':int(x.get('StartLine') or 1),'endLine':int(x.get('EndLine') or x.get('StartLine') or 1),'severity':'HIGH','description':f"Gitleaks обнаружил потенциальный секрет по правилу {x.get('RuleID') or 'unknown'}. Значение секрета скрыто.",'remediation':'Отозвать/ротировать секрет, удалить его из исходников и хранить в secret manager.','fingerprint':x.get('Fingerprint')})
    return findings, status


def semgrep():
    raw,status=run_json('semgrep',['semgrep','scan','--metrics=off','--json','--config','auto',str(PROJECT)],timeout=240)
    findings=[]
    for x in (raw.get('results',[]) if isinstance(raw,dict) else []):
        extra=x.get('extra') or {}; meta=extra.get('metadata') or {}; sev=(meta.get('severity') or extra.get('severity') or 'WARNING').upper()
        severity={'ERROR':'HIGH','WARNING':'MEDIUM','INFO':'LOW'}.get(sev,sev if sev in ('CRITICAL','HIGH','MEDIUM','LOW') else 'MEDIUM')
        findings.append({'category':'SAST','source':'Semgrep','path':relpath(x.get('path')),'class':x.get('check_id') or 'semgrep-finding','line':int((x.get('start') or {}).get('line') or 1),'endLine':int((x.get('end') or {}).get('line') or (x.get('start') or {}).get('line') or 1),'severity':severity,'description':extra.get('message') or 'Semgrep обнаружил потенциальную проблему.','remediation':(meta.get('fix') or meta.get('technology') or 'Изучить правило Semgrep и применить безопасный шаблон.'),'cwe':meta.get('cwe'),'owasp':meta.get('owasp'),'ruleId':x.get('check_id')})
    return findings,status


def osv():
    raw,status=run_json('osv-scanner',['osv-scanner','scan','source','--recursive','--format','json',str(PROJECT)],timeout=240)
    findings=[]
    results=raw.get('results',[]) if isinstance(raw,dict) else []
    for result in results:
        source=result.get('source') or {}; path=relpath(source.get('path') or 'dependency-manifest')
        for pkg in result.get('packages',[]):
            pinfo=pkg.get('package') or {}; group=pinfo.get('name',''); version=pinfo.get('version','')
            # Maven purl: pkg:maven/group/artifact@version
            purl=pinfo.get('purl','')
            if purl.startswith('pkg:maven/'):
                coord=purl[len('pkg:maven/'):].split('@',1); ga=coord[0].split('/',1)
                if len(ga)==2: group,artifact=ga; version=(coord[1].split('?',1)[0] if len(coord)>1 else version)
            else:
                artifact=group; group='unknown'
                if str(pinfo.get('ecosystem','')).lower()=='maven' and ':' in str(pinfo.get('name','')):
                    group,artifact=str(pinfo.get('name')).split(':',1)
            for vuln in pkg.get('vulnerabilities',[]):
                ids=vuln.get('aliases') or []; advisory=next((v for v in ids if v.startswith('CVE-')),vuln.get('id','OSV-UNKNOWN'))
                sev='HIGH'
                for sevdata in vuln.get('severity',[]):
                    score=str(sevdata.get('score',''))
                    if score.startswith('CVSS:'):
                        try:
                            base=float(score.split('/')[-1]); sev='CRITICAL' if base>=9 else 'HIGH' if base>=7 else 'MEDIUM' if base>=4 else 'LOW'
                        except Exception: pass
                findings.append({'category':'SCA','source':'OSV-Scanner','path':path,'group':group,'artifact':artifact,'version':version,'advisoryId':advisory,'severity':sev,'description':vuln.get('summary') or vuln.get('details','')[:500] or 'OSV-Scanner обнаружил уязвимую зависимость.','remediation':'Обновить зависимость до версии, не попадающей в affected ranges из advisory.','aliases':ids})
    return findings,status


def main():
    REPORT.mkdir(exist_ok=True)
    all_findings=[]; statuses={}
    for name,fn in [('gitleaks',gitleaks),('semgrep',semgrep),('osv-scanner',osv)]:
        f,s=fn(); all_findings.extend(f); statuses[name]=s
    # De-duplicate identical scanner hits without merging distinct tool evidence.
    seen=set(); unique=[]
    for f in all_findings:
        key=(f.get('category'),f.get('path'),f.get('class') or f.get('advisoryId'),f.get('line'),f.get('group'),f.get('artifact'),f.get('version'))
        if key not in seen: seen.add(key); unique.append(f)
    (REPORT/'external-findings.json').write_text(json.dumps({'findings':unique,'scanners':statuses},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'count':len(unique),'scanners':statuses},ensure_ascii=False))

if __name__=='__main__': main()
