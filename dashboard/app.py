import streamlit as st
import pandas as pd
import requests
from datetime import datetime, timedelta

KST_OFFSET = timedelta(hours=9)

st.set_page_config(page_title="Tribest ASM Dashboard", layout="wide")
st.markdown(
    """
    <style>
    html { scrollbar-gutter: stable; }
    [data-testid="stAppViewContainer"] { scrollbar-gutter: stable; }
    .section-label { font-size: 0.95rem; font-weight: 600; color: #4b5563; margin: 0.25rem 0 0.75rem 0; }
    .briefing-block-title { font-size: 1rem; font-weight: 700; margin: 0.25rem 0 0.5rem 0; }
    .briefing-list { font-size: 0.94rem; line-height: 1.75; }
    .briefing-meta { margin-top: 1rem; margin-bottom: 0.8rem; font-size: 0.84rem; line-height: 1.6; color: #6b7280; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "last_scan_data" not in st.session_state: st.session_state["last_scan_data"] = None
if "scan_queue" not in st.session_state: st.session_state["scan_queue"] = []
if "scan_queue_meta" not in st.session_state: st.session_state["scan_queue_meta"] = {}
if "batch_results" not in st.session_state: st.session_state["batch_results"] = []
if "selected_scan_id" not in st.session_state: st.session_state["selected_scan_id"] = None
if "selected_scan_profile" not in st.session_state: st.session_state["selected_scan_profile"] = "common"

# Main 브랜치의 상세한 카탈로그 사용
TARGET_CATALOG = [
    {"label": "OWASP Juice Shop", "short_label": "Juice Shop", "target": "juice-shop.lab.local", "ip": "172.28.0.11", "ports": "3000"},
    {"label": "Apache Tomcat PUT JSP Upload (tomcat/CVE-2017-12615)", "short_label": "Tomcat CVE-2017-12615", "target": "tomcat-cve-2017-12615.lab.local", "ip": "172.28.0.10", "ports": "8080"},
    {"label": "Redis Unauthorized Access (redis/4-unacc)", "short_label": "Redis 4-unacc", "target": "redis-4-unacc.lab.local", "ip": "172.28.0.20", "ports": "6379"},
    {"label": "SambaCry (samba/CVE-2017-7494)", "short_label": "SambaCry", "target": "sambacry.lab.local", "ip": "172.28.0.30", "ports": "445"},
    {"label": "MySQL Authentication Bypass (mysql/CVE-2012-2122)", "short_label": "MySQL CVE-2012-2122", "target": "mysql-cve-2012-2122.lab.local", "ip": "172.28.0.60", "ports": "3306"},
    {"label": "Elasticsearch Groovy Sandbox Escape (elasticsearch/CVE-2015-1427)", "short_label": "Elasticsearch CVE-2015-1427", "target": "elasticsearch-cve-2015-1427.lab.local", "ip": "172.28.0.70", "ports": "9200"},
    {"label": "vsftpd Backdoor (ftp/CVE-2011-2523)", "short_label": "vsftpd 2.3.4", "target": "vsftpd-2-3-4.lab.local", "ip": "172.28.0.80", "ports": "21"},
]

TARGET_LABEL_BY_TARGET = {item["target"]: item["label"] for item in TARGET_CATALOG}
TARGET_SHORT_LABEL_BY_TARGET = {item["target"]: item.get("short_label", item["label"]) for item in TARGET_CATALOG}

# Main 브랜치의 상세한 프로필 설명 및 세부 내용 사용
SCAN_PROFILES = {
    "quick": "핵심 포트만 빠르게 확인합니다. 실습 자산 점검용입니다.",
    "common": "자주 쓰이는 상위 100개 포트를 확인합니다. 기본값으로 쓰기 적절합니다.",
    "deep": "상위 1000개 포트를 확인합니다. 시간이 더 걸리지만 일반적인 서비스 노출 확인에 유리합니다.",
    "full": "1-65535 전체 포트를 확인합니다. 가장 느리지만 범위가 가장 넓습니다.",
    "web": "웹 서비스 포트(80/443/3000/8080/8443)를 중심으로 확인합니다.",
}

SCAN_PROFILE_DETAILS = {
    "quick": {
        "title": "Quick",
        "summary": "프로젝트에서 자주 보는 핵심 포트만 빠르게 확인합니다.",
        "ports": "21, 22, 80, 139, 443, 445, 3000, 8080, 3306, 6379, 9200",
        "command": "nmap -sV -p 21,22,80,139,443,445,3000,8080,3306,6379,9200 <target>",
    },
    "common": {
        "title": "Common",
        "summary": "Nmap의 상위 100개 포트 집합을 기준으로 서비스 버전을 확인합니다.",
        "ports": "Nmap top ports 100",
        "command": "nmap -sV --top-ports 100 <target>",
    },
    "deep": {
        "title": "Deep",
        "summary": "Nmap의 상위 1000개 포트 집합을 기준으로 더 넓게 확인합니다.",
        "ports": "Nmap top ports 1000",
        "command": "nmap -sV --top-ports 1000 <target>",
    },
    "full": {
        "title": "Full",
        "summary": "1-65535 전체 포트를 전부 확인합니다.",
        "ports": "1-65535",
        "command": "nmap -sV -p- <target>",
    },
    "web": {
        "title": "Web",
        "summary": "웹 서비스 탐지에 자주 쓰이는 포트만 묶어서 확인합니다.",
        "ports": "80, 443, 3000, 8080, 8443",
        "command": "nmap -sV -p 80,443,3000,8080,8443 <target>",
    },
}

def convert_to_kst(raw_time_str, fmt="%Y-%m-%d %H:%M:%S"):
    if not raw_time_str: return "N/A"
    try:
        clean_str = raw_time_str.replace("T", " ").replace("Z", "")[:19]
        dt_utc = datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S")
        dt_kst = dt_utc + KST_OFFSET
        return dt_kst.strftime(fmt)
    except Exception:
        return str(raw_time_str)

def get_all_scans(url):
    try:
        res = requests.get(f"{url}/api/v1/scans", timeout=2)
        if res.status_code == 200:
            data = res.json()
            items = data.get("items", []) if isinstance(data, dict) else data
            return sorted(items, key=lambda x: str(x.get("created_at", "")), reverse=True)
        return []
    except Exception: return []

@st.cache_data(ttl=60)
def get_scenarios(url):
    try:
        res = requests.get(f"{url}/api/v1/scenarios", timeout=5)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list): return data
            if isinstance(data, dict) and "items" in data: return data["items"]
    except Exception: pass
    return []

def get_ollama_models(url, base_url):
    try:
        res = requests.get(f"{url}/api/v1/ai/ollama/models", params={"base_url": base_url}, timeout=5)
        if res.status_code == 200: return res.json()
    except Exception: pass
    return {"available": False, "models": [], "error": "backend request failed"}

def get_target_label(target: str) -> str: return TARGET_LABEL_BY_TARGET.get(target, target)
def get_target_short_label(target: str) -> str: return TARGET_SHORT_LABEL_BY_TARGET.get(target, target)

def get_scan_detail(url, scan_id, *, include_report=True):
    try:
        scan_res = requests.get(f"{url}/api/v1/scans/{scan_id}", timeout=5).json()
        analysis_res = requests.get(f"{url}/api/v1/analyses/{scan_id}", timeout=5).json()
    except Exception: return None
    report_payload, report_error = ({}, None)
    if include_report: report_payload, report_error = get_report_detail(url, scan_id)
    return {
        "scan_result": scan_res,
        "analysis_result": analysis_res,
        "report_result": report_payload,
        "report_error": report_error,
    }

def get_report_detail(url, scan_id):
    report_error, report_payload = (None, {})
    try:
        report_res = requests.get(f"{url}/api/v1/reports/{scan_id}", timeout=30)
        report_payload = report_res.json() if report_res.status_code == 200 else {}
        if report_res.status_code != 200: report_error = f"report request failed ({report_res.status_code})"
    except Exception as exc: report_error = str(exc)
    return report_payload, report_error

def regenerate_report_detail(url, scan_id, *, narrative_backend="template", gemini_api_key="", gemini_model="", ollama_base_url="", ollama_model=""):
    report_error, report_payload = (None, {})
    try:
        report_params = {"narrative_backend": narrative_backend}
        if narrative_backend == "gemini" and gemini_api_key: report_params["gemini_api_key"] = gemini_api_key
        if narrative_backend == "gemini" and gemini_model: report_params["gemini_model"] = gemini_model
        if narrative_backend == "ollama" and ollama_base_url: report_params["ollama_base_url"] = ollama_base_url
        if narrative_backend == "ollama" and ollama_model: report_params["ollama_model"] = ollama_model
        report_res = requests.post(f"{url}/api/v1/reports/{scan_id}/regenerate", params=report_params, timeout=180)
        report_payload = report_res.json() if report_res.status_code == 200 else {}
        if report_res.status_code != 200: report_error = f"report regenerate failed ({report_res.status_code})"
    except Exception as exc: report_error = str(exc)
    return report_payload, report_error

def get_verifications(url, scan_id):
    try:
        res = requests.get(f"{url}/api/v1/verifications/{scan_id}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            
            # 케이스 A: 백엔드가 리스트를 "items"에 담아줄 때
            if isinstance(data, dict) and "items" in data:
                return data["items"]
                
            # 케이스 B: 영빈님 데이터처럼 "results" 안에 "service", "risk"로 나뉘어 올 때
            if isinstance(data, dict) and "results" in data:
                r = data["results"]
                return r.get("service", []) + r.get("risk", [])
                
            # 케이스 C: 그냥 리스트 자체로 올 때
            if isinstance(data, list):
                return data
                
        return []
    except Exception: return []

def render_dashboard(url, data):
    if not data: return
    scan_res = data.get("scan_result", {})
    analysis_res = data.get("analysis_result", {})
    report_res = data.get("report_result", {})
    report_error = data.get("report_error")
    drift_info = analysis_res.get("drift", {})
    scan_id = scan_res.get("scan_id")

    st.divider()

    new_p = drift_info.get("new_ports", [])
    closed_p = drift_info.get("closed_ports", [])
    if new_p or closed_p:
        st.warning("인프라 변화 감지 (Drift Detected)")
        if new_p: st.info(f"새 포트: {new_p}")
        if closed_p: st.info(f"닫힌 포트: {closed_p}")
    else:
        st.success("포트 변화 없음")

    r_info = analysis_res.get("analysis", {}).get("risk_summary", {})
    vulns = analysis_res.get("analysis", {}).get("vulnerabilities", [])

    col1, col2, col3 = st.columns(3)
    col1.metric("위험 점수", f"{r_info.get('score', 0)}점")
    col2.metric("등급", r_info.get("grade", "N/A"))
    col3.metric("취약점 수", f"{len(vulns)}개")
    st.caption(f"현재 스캔 ID: {scan_id}")

    t_ai, t_ports, t_vulns, t_verify, t_logs, t_json = st.tabs(["🤖 AI 브리핑", "🌐 포트 현황", "🚨 취약점 상세", "✅ 검증(PoC)", "📝 Raw 로그", "🧾 JSON"])

    with t_ai:
        narrative = report_res.get("narrative", {})
        combo_data = report_res.get("combination_breakdown", [])
        host_context = report_res.get("host_context", {})

        if report_error: st.warning(f"AI 브리핑 조회 실패: {report_error}")

        if narrative and (narrative.get("generated") or narrative.get("backend") == "template"):
            st.markdown("<div class='briefing-block-title'>🧭 브리핑 요약</div>", unsafe_allow_html=True)
            st.info(narrative.get("summary", ""))
            if narrative.get("full_briefing"):
                st.markdown("<div class='briefing-block-title'>📝 브리핑 본문</div>", unsafe_allow_html=True)
                st.write(narrative.get("full_briefing"))
            if narrative.get("fallback_reason"):
                st.caption(f"Fallback reason: {narrative.get('fallback_reason')}")
                
            # 질문자님 코드 반영 (2단 분리 레이아웃)
            ca1, ca2 = st.columns(2)
            with ca1:
                st.markdown("<div class='briefing-block-title'>🔴 위험 분석</div>", unsafe_allow_html=True)
                for reason in narrative.get("risk_explanation", []): st.markdown(f"<div class='briefing-list'>- {reason}</div>", unsafe_allow_html=True)
            with ca2:
                st.markdown("<div class='briefing-block-title'>🛡️ 대응 방안</div>", unsafe_allow_html=True)
                for action in narrative.get("recommended_action", []): st.markdown(f"<div class='briefing-list'>- {action}</div>", unsafe_allow_html=True)
        else:
            st.warning("🤖 AI 리포트 생성 대기 중입니다. (분석 완료 후 반영 예정)")

        # Main 코드 반영 (메타데이터 및 Raw JSON 팝오버)
        if narrative:
            if narrative.get("backend") == "template": generation_status = "기본 브리핑"
            elif narrative.get("fallback_reason"): generation_status = "Fallback"
            elif narrative.get("generated"): generation_status = "AI 생성"
            else: generation_status = "미생성"
            st.markdown(
                (
                    "<div class='briefing-meta'>"
                    + " | ".join(
                        [
                            f"브리핑 엔진: {str(narrative.get('backend', 'unknown')).upper()}",
                            f"모델: {narrative.get('model') or '-'}",
                            f"생성 상태: {generation_status}",
                        ]
                    )
                    + "</div>"
                ),
                unsafe_allow_html=True,
            )
            with st.expander("AI 브리핑 원본"):
                st.json({
                    "backend": narrative.get("backend"),
                    "model": narrative.get("model"),
                    "generated": narrative.get("generated"),
                    "fallback_reason": narrative.get("fallback_reason"),
                    "raw_response": narrative.get("raw_response"),
                })

        if combo_data or host_context:
            st.divider()
            if host_context: 
                st.write(f"호스트 가점: +{host_context.get('bonus', 0)}")
                st.caption(host_context.get("narrative_hint", ""))
            for combo in combo_data:
                with st.expander(f"위험 조합: {combo.get('label', 'unknown')}"):
                    st.write(f"서비스: {', '.join(combo.get('services', []))}")
                    st.write(f"포트: {', '.join(map(str, combo.get('ports', [])))}")
                    for evidence in combo.get("evidence", []): st.write(f"- {evidence}")

    with t_ports:
        p_list = scan_res.get("scan", {}).get("ports", [])
        if p_list:
            df = pd.DataFrame([{"포트": p["port"], "서비스": p["service"]["name"], "제품": p["service"].get("product"), "버전": p["service"].get("version")} for p in p_list])
            st.dataframe(df, use_container_width=True, hide_index=True)

    with t_vulns:
        if vulns: st.dataframe(pd.DataFrame(vulns), use_container_width=True, hide_index=True)
        else: st.success("발견된 취약점이 없습니다.")

    with t_verify:
        st.subheader("✅ 자동 검증(PoC) 결과 상세")
        verifications = get_verifications(url, scan_id)
        
        if verifications:
            for v in verifications:
                # 데이터가 없으면 에러를 내지 않고 "N/A"나 기본값을 반환 (.get의 위력)
                v_template = v.get("template_id", "Unknown Template")
                v_target = v.get("target", "Unknown Target")
                v_status = v.get("status", "N/A")
                v_method = v.get("method", "N/A")
                v_type = v.get("verification_type", "N/A")
                v_port = v.get("matched_port", "N/A")
                
                icon_status = "🟢" if v_status == "verified" else "🟡" if v_status == "suspected" else "🔴"

                expander_title = f"[{icon_status} {v_status.upper()}] {v_template} ({v_type}) ➔ Port: {v_port}"
                
                with st.expander(expander_title):
                    v_col1, v_col2, v_col3 = st.columns(3)
                    v_col1.write(f"**검증 방식:** {v_method}")
                    v_col2.write(f"**검증 타입:** `{v_type}`")
                    v_col3.write(f"**매칭 포트:** `{v_port}`")
                    
                    v_col4, v_col5, v_col6 = st.columns(3)
                    v_col4.write(f"**검증 상태:** {v_status}")
                    v_col5.write(f"**대상 타깃:** {v_target}")
                    v_col6.write(f"**검증 시각:** {convert_to_kst(v.get('created_at'))}")
                    
                    st.divider()
                    st.write("**🔍 증거 자료 (Evidence)**")
                    st.info(v.get("evidence", "기록된 증거가 없습니다."))
                    
                    raw_data = v.get("raw_output") or v.get("raw")
                    if raw_data:
                        if st.toggle("**📄 Raw Output 상세보기**", key=f"toggle_raw_{v_template}"):
                            st.code(raw_data, language="json")
        else:
            st.info("이 타깃에 대해 실행된 자동 검증 이력이 없습니다.")

    with t_logs:
        for log in scan_res.get("scan", {}).get("logs", []):
            st.caption(f"Source: {log.get('source')} | Phase: {log.get('phase')} | Return: {log.get('return_code')} | Cmd: {log.get('command')}")
            if log.get("stdout"): st.code(log.get("stdout"))
            if log.get("stderr"): st.error(log.get("stderr"))

    with t_json:
        json_tab1, json_tab2, json_tab3 = st.tabs(["Scan", "Analysis", "Report"])
        with json_tab1: st.json(scan_res)
        with json_tab2: st.json(analysis_res)
        with json_tab3: st.json(report_res)


backend_url = st.sidebar.text_input("Backend URL", value="http://backend:8000")
st.sidebar.subheader("AI 브리핑 설정")
ai_backend = st.sidebar.selectbox("브리핑 엔진", ["template", "gemini", "ollama"], format_func=lambda key: {"template": "Template", "gemini": "Gemini", "ollama": "Ollama"}[key])
gemini_model, gemini_api_key, ollama_base_url, ollama_model = "", "", "", ""
if ai_backend == "gemini":
    gemini_model = st.sidebar.text_input("Gemini 모델", value="gemini-3-flash-preview")
    gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password")
elif ai_backend == "ollama":
    ollama_base_url = st.sidebar.text_input("Ollama URL", value="http://host.docker.internal:11434")
    ollama_info = get_ollama_models(backend_url, ollama_base_url)
    if ollama_info.get("available"):
        st.sidebar.success("Ollama 연결됨")
        model_options = ollama_info.get("models", [])
        default_model = "llama3.1:8b" if "llama3.1:8b" in model_options else (model_options[0] if model_options else "")
        default_index = model_options.index(default_model) if default_model in model_options else 0
        if model_options: ollama_model = st.sidebar.selectbox("Ollama 모델", model_options, index=default_index)
        else:
            st.sidebar.warning("Ollama 모델 목록이 비어 있습니다.")
            st.sidebar.selectbox("Ollama 모델", ["모델 없음"], index=0, disabled=True)
    else:
        st.sidebar.warning("Ollama가 실행 중이 아니거나 연결할 수 없습니다.")
        st.sidebar.selectbox("Ollama 모델", ["Ollama 연결 필요"], index=0, disabled=True)
        st.sidebar.caption(ollama_info.get("error", ""))

scans_list = get_all_scans(backend_url)
st.sidebar.metric("누적 스캔", len(scans_list))

st.sidebar.subheader("📜 스캔 이력")
if scans_list:
    history_options = []
    for s in scans_list:
        sid = s.get("scan_id") or s.get("id")
        target = str(s.get("target", ""))
        target_label = get_target_label(target)
        target_short_label = get_target_short_label(target)
        label = f"[{convert_to_kst(s.get('created_at'), '%m/%d %H:%M:%S')}] {target_short_label}"
        history_options.append({"label": label, "scan_id": sid, "target": target, "target_label": target_label, "created_at": s.get("created_at")})
    sel_label = st.sidebar.selectbox("기록 선택", [item["label"] for item in history_options])
    selected_history = next(item for item in history_options if item["label"] == sel_label)
    selected_history_id = selected_history["scan_id"]
    
    # Main 코드 반영 (사이드바 상세 캡션)
    st.sidebar.caption(f"자산: {selected_history['target_label']}")
    st.sidebar.caption(f"대상값: {selected_history['target']}")
    st.sidebar.caption(f"스캔 ID: {selected_history_id}")
    st.sidebar.caption(f"생성 시각: {convert_to_kst(selected_history['created_at'])}")
    
    if st.sidebar.button("불러오기", use_container_width=True):
        loaded = get_scan_detail(backend_url, selected_history_id)
        st.session_state["last_scan_data"] = loaded
        st.session_state["batch_results"] = [loaded] if loaded else []
        st.session_state["selected_scan_id"] = selected_history_id if loaded else None
        st.rerun()

st.title("Tribest ASM Dashboard")

with st.expander("🌐 대역 기반 자산 스캔 (Inventory Drift)", expanded=False):
    inv_col1, inv_col2 = st.columns([3, 1])
    scope_input = inv_col1.text_input("IP 대역 (Scope)", value="172.28.0.0/24")
    inv_profile = inv_col2.selectbox("대역 스캔용 프로필", list(SCAN_PROFILES.keys()), key="inv_profile_select")
    
    if st.button("대역 탐색 및 대기 목록에 추가", type="primary", use_container_width=True):
        with st.spinner(f"[{scope_input}] 대역 내 활성 호스트 탐색 중..."):
            try:
                res = requests.post(f"{backend_url}/api/v1/inventories/run", json={"scope": scope_input, "profile": inv_profile}, timeout=300)
                if res.status_code == 200:
                    inv_data = res.json()
                    discovered_hosts = inv_data.get("hosts", [])
                    drift_data = inv_data.get("drift", {}) or {}

                    if discovered_hosts:
                        added_count = 0
                        for h in discovered_hosts:
                            host_ip = h["ip"] if isinstance(h, dict) else str(h)
                            if host_ip not in st.session_state["scan_queue"]:
                                st.session_state["scan_queue"].append(host_ip)
                                added_count += 1
                        st.success(f"✅ {added_count}개의 활성 호스트를 🚀 스캔 대기 목록에 추가했습니다! (아래에서 스캔을 시작해 주세요)")
                    else:
                        st.warning("이 대역에서 발견된 활성 호스트가 없습니다.")

                    new_hosts = drift_data.get("new_hosts", []) or []
                    missing_hosts = drift_data.get("missing_hosts", []) or []
                    changed_hosts = drift_data.get("changed_hosts", []) or []

                    if new_hosts or missing_hosts or changed_hosts:
                        st.warning("🚨 대역 변화 감지 (Inventory Drift Detected)")

                        if new_hosts:
                            st.info("🟢 새로 나타난 호스트: " + ", ".join(new_hosts))

                        if missing_hosts:
                            st.error("🔴 사라진 호스트: " + ", ".join(missing_hosts))

                        if changed_hosts:
                            changed_lines = []
                            for ch in changed_hosts:
                                ip = ch.get("ip", "unknown")
                                new_ports = ch.get("new_ports", []) or []
                                closed_ports = ch.get("closed_ports", []) or []

                                parts = [f"{ip}"]
                                if new_ports:
                                    parts.append(f"+{new_ports}")
                                if closed_ports:
                                    parts.append(f"-{closed_ports}")
                                changed_lines.append(" / ".join(parts))

                            st.info("🟡 포트가 바뀐 호스트:\n- " + "\n- ".join(changed_lines))
                    else:
                        st.success("대역 변화 없음")
                else:
                    st.error(f"❌ 탐색 실패 (상태 코드: {res.status_code})")
            except Exception as e:
                st.error(f"서버 통신 에러: {e}")

with st.expander("🚀 타깃 스캔 실행 (단일/병렬)", expanded=True):
    df_targets = pd.DataFrame([{"자산": item["label"], "식별자": item["target"], "IP": item["ip"], "예상 노출 포트": item["ports"]} for item in TARGET_CATALOG])
    st.dataframe(df_targets, use_container_width=True, hide_index=True)

    scan_col1, scan_col2 = st.columns(2)
    
    # Main 코드 반영 (프로필 선택 UI 및 팝오버)
    profile_caption_col, profile_detail_col = scan_col1.columns([6, 1])
    profile = profile_caption_col.selectbox("포트 스캔 프로필", list(SCAN_PROFILES.keys()), index=list(SCAN_PROFILES.keys()).index(st.session_state["selected_scan_profile"]))
    st.session_state["selected_scan_profile"] = profile
    profile_caption_col.caption(SCAN_PROFILES[profile])
    with profile_detail_col.popover("상세", use_container_width=True):
        profile_info = SCAN_PROFILE_DETAILS[profile]
        st.write(f"**{profile_info['title']}**")
        st.write(profile_info["summary"])
        st.write(f"대상 포트: {profile_info['ports']}")
        st.code(profile_info["command"])
    
    scenarios_list = get_scenarios(backend_url)
    scenario_options = ["선택 안 함"]
    for s in scenarios_list:
        if isinstance(s, dict): scenario_options.append(str(s.get("id") or s.get("name") or s))
        else: scenario_options.append(str(s))
        
    selected_scenario = scan_col2.selectbox("시나리오 선택", scenario_options)
    final_scenario = None if selected_scenario == "선택 안 함" else selected_scenario

    header_col1, header_col2, header_col3 = st.columns([2, 2, 1])
    header_col1.write("타깃 선택")
    header_col2.write("입력")

    input_col1, input_col2, input_col3 = st.columns([2, 2, 1])
    selected_label = input_col1.selectbox("타깃 선택", [item["label"] for item in TARGET_CATALOG], label_visibility="collapsed")
    selected_item = next(item for item in TARGET_CATALOG if item["label"] == selected_label)
    manual_target = input_col2.text_input("입력", key="manual-target-input", placeholder="예: redis-4-unacc.lab.local", label_visibility="collapsed")
    
    if input_col3.button("목록 비우기", key="clear-scan-queue", use_container_width=True):
        st.session_state["scan_queue"] = []
        st.session_state["scan_queue_meta"] = {}
        st.rerun()

    action_trigger = None
    button_col1, button_col2, button_col3 = st.columns([2, 2, 1])

    if button_col1.button("타깃 추가", key="add-catalog-target", use_container_width=True):
        candidate = selected_item["target"]
        if candidate not in st.session_state["scan_queue"]: st.session_state["scan_queue"].append(candidate)
        st.rerun()

    if button_col2.button("수동 추가", key="add-manual-target", use_container_width=True):
        candidate = manual_target.strip()
        if candidate and candidate not in st.session_state["scan_queue"]: st.session_state["scan_queue"].append(candidate)
        st.rerun()

    if button_col3.button("스캔 시작", key="run-scan-queue", type="primary", use_container_width=True):
        action_trigger = "run"

    targets_to_run = list(st.session_state["scan_queue"])

    if targets_to_run:
        st.caption("최종 대기 목록")
        remove_target = None 
        for idx, target in enumerate(targets_to_run):
            meta = st.session_state["scan_queue_meta"].get(
                target,
                {"status": "unknown", "open_ports": []}
            )
            row_col, remove_col = st.columns([5, 1])
            status = meta.get("status", "unknown")
            open_ports = meta.get("open_ports", [])

            row_col.write(f"{idx + 1}. `{target}` | status: `{status}` | open_ports: `{open_ports}`")
            if remove_col.button("삭제", key=f"remove-{idx}", use_container_width=True): remove_target = target
        if remove_target is not None:
            st.session_state["scan_queue"] = [item for item in st.session_state["scan_queue"] if item != remove_target]
            st.rerun()

    if action_trigger == "run":
        if not targets_to_run:
            st.warning("타겟을 선택하세요.")
        else:
            completed_results = []

            if len(targets_to_run) > 1:
                with st.spinner(f"{len(targets_to_run)}개 타깃 병렬 스캔 중..."):
                    try:
                        batch_payload = {
                            "targets": targets_to_run,
                            "profile": profile,
                            "scenario": final_scenario,
                            "max_concurrency": 4
                        }
                        res = requests.post(f"{backend_url}/api/v1/workflows/run-batch", json=batch_payload, timeout=600)
                        if res.status_code == 200:
                            batch_data = res.json()
                            for item in batch_data.get("items", []):
                                t_target = item.get("target")
                                if item.get("status") == "completed":
                                    c_scan_id = item.get("scan_id")
                                    regenerate_report_detail(backend_url, c_scan_id, narrative_backend=ai_backend, gemini_api_key=gemini_api_key, gemini_model=gemini_model, ollama_base_url=ollama_base_url, ollama_model=ollama_model)
                                    detail = get_scan_detail(backend_url, c_scan_id)
                                    if detail: completed_results.append(detail)
                                    st.success(f"✅ {t_target} 완료")
                                else:
                                    st.error(f"❌ {t_target} 실패: {item.get('error', 'Unknown Error')}")
                        else:
                            st.error("❌ 병렬 스캔 API 호출 실패")
                    except Exception as e:
                        st.error(f"Error: {e}")
            else:
                target = targets_to_run[0]
                with st.spinner(f"[{target}] 분석 중..."):
                    try:
                        single_payload = {"target": target, "profile": profile, "scenario": final_scenario}
                        res = requests.post(f"{backend_url}/api/v1/workflows/run", json=single_payload, timeout=300)
                        if res.status_code == 200:
                            current_scan_id = res.json()["scan_result"]["scan_id"]
                            regenerate_report_detail(backend_url, current_scan_id, narrative_backend=ai_backend, gemini_api_key=gemini_api_key, gemini_model=gemini_model, ollama_base_url=ollama_base_url, ollama_model=ollama_model)
                            detail = get_scan_detail(backend_url, current_scan_id)
                            if detail: completed_results.append(detail)
                            st.success(f"✅ {target} 완료")
                        else:
                            st.error(f"❌ {target} 실패")
                    except Exception as e:
                        st.error(f"Error: {e}")

            if completed_results:
                st.session_state["batch_results"] = completed_results
                st.session_state["last_scan_data"] = completed_results[-1]
                st.session_state["selected_scan_id"] = completed_results[-1]["scan_result"]["scan_id"]
            st.rerun()

if st.session_state["batch_results"]:
    if len(st.session_state["batch_results"]) > 1:
        st.caption("이번 실행 결과")
        result_labels = {}
        for item in st.session_state["batch_results"]:
            scan_id = item["scan_result"]["scan_id"]
            target = item["scan_result"]["target"]["input_value"]
            risk = item["analysis_result"].get("analysis", {}).get("risk_summary", {})
            label = f"{target} | {risk.get('grade', 'n/a')} | {scan_id}"
            result_labels[label] = scan_id
        current_scan_id = st.selectbox("결과 선택", list(result_labels.keys()), index=next((idx for idx, key in enumerate(result_labels.keys()) if result_labels[key] == st.session_state["selected_scan_id"]), len(result_labels) - 1))
        st.session_state["selected_scan_id"] = result_labels[current_scan_id]
    
    selected_data = next((item for item in st.session_state["batch_results"] if item["scan_result"]["scan_id"] == st.session_state["selected_scan_id"]), st.session_state["batch_results"][-1])
    st.session_state["last_scan_data"] = selected_data

if st.session_state["last_scan_data"]:
    render_dashboard(backend_url, st.session_state["last_scan_data"])