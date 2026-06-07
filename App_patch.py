# Patch script — fixes tab counts + adds Behavioral panel + Scan History
# Run on VM: python3 App_patch.py

import re

path = '/home/pratham/apkguard/frontend/src/App.jsx'
with open(path) as f:
    content = f.read()

original_len = len(content)

# ── Fix 1: Tab filter counts — severities may be mixed case ──────────────────
# The tab filter compares f.severity === filter (e.g. "CRITICAL")
# But findings from backend may have "Critical" or "critical"
# Fix: normalize in the filter
old_visible = 'const visible=filter==="ALL"?findings:findings.filter(f=>f.severity===filter);'
new_visible = 'const visible=filter==="ALL"?findings:findings.filter(f=>(f.severity||"").toUpperCase()===filter.toUpperCase());'
if old_visible in content:
    content = content.replace(old_visible, new_visible)
    print("Fix 1 applied: tab filter normalized")
else:
    print("Fix 1 skipped (already fixed or different string)")

# ── Fix 2: Tab count also needs normalization ─────────────────────────────────
old_tabcount = 't==="ALL"?findings.length:findings.filter(f=>f.severity===t).length'
new_tabcount = 't==="ALL"?findings.length:findings.filter(f=>(f.severity||"").toUpperCase()===t.toUpperCase()).length'
if old_tabcount in content:
    content = content.replace(old_tabcount, new_tabcount)
    print("Fix 2 applied: tab count normalized")
else:
    print("Fix 2 skipped")

# ── Fix 3: Add BehavioralPanel component before ResultsDashboard ──────────────
behavioral_component = '''
/* ── Behavioral Analysis Panel ───────────────────────────────────────────── */
function BehavioralPanel({behavioral}){
  if(!behavioral)return null;
  const behaviors=behavioral.dynamic_behaviors||[];
  const indicators=behavioral.runtime_indicators||[];
  const antiAnalysis=behavioral.anti_analysis_techniques||[];
  if(behaviors.length===0&&indicators.length===0)return null;
  const sevColor=(s)=>s==="Critical"?"var(--c-critical)":s==="High"?"var(--c-high)":s==="Medium"?"var(--c-medium)":"var(--c-low)";
  const catColor=(c)=>c==="Surveillance"?"#8b5cf6":c==="Data Exfiltration"?"#ef4444":c==="Credential Theft"?"#f97316":c==="Persistence"?"#f59e0b":"#38bdf8";
  return(
    <div className="panel">
      <div className="panel-head">
        <Activity size={16}/>Behavioral Analysis
        <span className="panel-count">{behaviors.length} behaviors · {indicators.length} indicators</span>
        {antiAnalysis.length>0&&<span className="danger-count">{antiAnalysis.length} evasion</span>}
      </div>
      {behaviors.length>0&&(
        <div style={{padding:"10px 14px"}}>
          <div className="ai-section-head" style={{marginBottom:"8px"}}>Dynamic Behaviors</div>
          {behaviors.map((b,i)=>(
            <div key={i} style={{display:"flex",alignItems:"flex-start",gap:"8px",padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
              <span style={{fontSize:"10px",fontFamily:"var(--font-mono)",color:sevColor(b.severity),background:`${sevColor(b.severity)}22`,border:`1px solid ${sevColor(b.severity)}44`,borderRadius:"4px",padding:"2px 6px",flexShrink:0,marginTop:"1px"}}>{b.severity||"Medium"}</span>
              <div>
                <div style={{fontSize:"12px",fontWeight:"500",color:"var(--text-0)"}}>{b.behavior}</div>
                <div style={{fontSize:"11px",color:"var(--text-1)",marginTop:"2px"}}>{b.description}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {indicators.length>0&&(
        <div style={{padding:"0 14px 12px"}}>
          <div className="ai-section-head" style={{margin:"8px 0"}}>Runtime Indicators</div>
          <div className="perm-grid">
            {indicators.map((ind,i)=>(
              <div key={i} className="perm-chip" style={{color:catColor(ind.category),background:`${catColor(ind.category)}11`,borderColor:`${catColor(ind.category)}33`,display:"flex",alignItems:"center",gap:"4px"}}>
                <span style={{fontSize:"9px"}}>{ind.category}</span>
                <span style={{color:"var(--text-0)"}}>{ind.indicator}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {antiAnalysis.length>0&&(
        <div style={{padding:"0 14px 12px",background:"rgba(239,68,68,0.03)"}}>
          <div className="ai-section-head" style={{margin:"8px 0",color:"var(--c-critical)"}}>Anti-Analysis Techniques</div>
          {antiAnalysis.map((a,i)=>(
            <div key={i} style={{fontSize:"11px",color:"var(--text-1)",padding:"3px 0",display:"flex",gap:"6px"}}>
              <span style={{fontFamily:"var(--font-mono)",color:"var(--c-critical)",fontSize:"10px"}}>{a.technique}</span>
              <span>{a.description}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Scan History Panel ──────────────────────────────────────────────────── */
function ScanHistoryPanel({onSelectScan}){
  const [history,setHistory]=React.useState([]);
  const [loading,setLoading]=React.useState(true);
  React.useEffect(()=>{
    fetch('http://localhost:8000/history')
      .then(r=>r.json())
      .then(d=>{ setHistory(d.scans||[]); setLoading(false); })
      .catch(()=>setLoading(false));
  },[]);
  if(loading)return null;
  if(history.length===0)return null;
  const scoreColor=(s)=>s>=80?"var(--c-critical)":s>=60?"var(--c-high)":s>=40?"var(--c-medium)":s>=20?"var(--c-low)":"#22c55e";
  return(
    <div className="panel" style={{marginBottom:"16px"}}>
      <div className="panel-head"><Clock size={16}/>Recent Scans<span className="panel-count">{history.length} scans</span></div>
      <div style={{padding:"8px"}}>
        {[...history].reverse().slice(0,5).map((s,i)=>(
          <div key={i} style={{display:"flex",alignItems:"center",gap:"10px",padding:"7px 8px",borderRadius:"6px",cursor:"pointer",transition:"background 0.15s"}}
            onMouseEnter={e=>e.currentTarget.style.background="var(--bg-card-h)"}
            onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <div style={{width:"36px",height:"36px",borderRadius:"8px",background:`${scoreColor(s.risk_score)}22`,border:`1px solid ${scoreColor(s.risk_score)}44`,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"var(--font-mono)",fontSize:"12px",fontWeight:"bold",color:scoreColor(s.risk_score),flexShrink:0}}>{s.risk_score}</div>
            <div style={{minWidth:0,flex:1}}>
              <div style={{fontSize:"12px",fontWeight:"500",color:"var(--text-0)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{s.filename}</div>
              <div style={{fontSize:"10px",color:"var(--text-2)",fontFamily:"var(--font-mono)"}}>{s.package||"Unknown package"}</div>
            </div>
            <div style={{fontSize:"10px",color:"var(--text-2)",flexShrink:0}}>{new Date(s.scan_time).toLocaleTimeString()}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
'''

# Insert before ResultsDashboard
target = 'function ResultsDashboard({'
if behavioral_component.strip()[:30] not in content and target in content:
    content = content.replace(target, behavioral_component + '\nfunction ResultsDashboard({', 1)
    print("Fix 3 applied: BehavioralPanel + ScanHistoryPanel added")
else:
    print("Fix 3 skipped (already exists)")

# ── Fix 4: Add React import (needed for useState in ScanHistoryPanel) ─────────
if "import React" not in content and "import { useState" in content:
    content = content.replace(
        'import { useState, useCallback, useRef }',
        'import React, { useState, useCallback, useRef }'
    )
    print("Fix 4 applied: React import added")
else:
    print("Fix 4 skipped")

# ── Fix 5: Add Clock icon to lucide imports ───────────────────────────────────
if "Clock" not in content:
    content = content.replace(
        'Search, Globe, Package, BarChart2,',
        'Search, Globe, Package, BarChart2, Clock,'
    )
    print("Fix 5 applied: Clock icon added")
else:
    print("Fix 5 skipped")

# ── Fix 6: Wire BehavioralPanel and ScanHistoryPanel into dashboard ───────────
# Add behavioral after right-col opening, and history before hero-row
old_rightcol = '<div className="right-col"><AIPanel ai={aiAnalysis}/><PermissionsPanel permissions={perms}/></div>'
new_rightcol = '<div className="right-col"><AIPanel ai={aiAnalysis}/><BehavioralPanel behavioral={data.behavioral}/><PermissionsPanel permissions={perms}/></div>'
if old_rightcol in content and 'BehavioralPanel behavioral' not in content:
    content = content.replace(old_rightcol, new_rightcol)
    print("Fix 6 applied: BehavioralPanel wired into dashboard")
else:
    print("Fix 6 skipped")

# Add ScanHistory above hero row
old_hero = '<div className="hero-row">'
new_hero = '<ScanHistoryPanel/>\n      <div className="hero-row">'
if old_hero in content and 'ScanHistoryPanel' not in content:
    content = content.replace(old_hero, new_hero, 1)
    print("Fix 7 applied: ScanHistoryPanel added to dashboard")
else:
    print("Fix 7 skipped")

# Save
with open(path, 'w') as f:
    f.write(content)

print(f"\nDone. File: {len(content)} chars (was {original_len})")
