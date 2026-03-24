# Verify 기능 가이드
`analysis/verify.py` 기준으로 현재 구현된 verify 기능을 정리한 문서.
스캔 결과와 분석 결과를 바탕으로, `nuclei` 템플릿을 이용해 서비스 존재 여부와 위험 신호를 한번 더 확인하는 후속 검증 단계이다.

---

## 1. 검증
### service 검증 
 - 해당 포트에 감지된 서비스가 실제로 존재하는지
 - 타겟 : `redis 4.0.14`, `samba`, `tomcat 8.5.19`, `vsftpd 2.3.4`, `elasticsearch 1.4.2`
 - `analysis/verification/service`
### risk 검증
 - 해당 서비스에서 실제 위험 징후가 나타나는지
 - 타겟 : `redis - unauth/rce`, `tomcat - put`, `vsftpd - backdoor`, `elasticsearch - groovy`
 - `analysis/verification/risk`

<br></br>

## 2. 결과 형태
### 전체 형태
```
{
  "scan_id": "...",
  "target_type": "...",                       # ex ) redis, tomcat, ...
  "target": "...",
  "results": {
    "service": [<verification dict>],         # 서비스 검증 결과
    "risk": [<verification dict>]             # 위험 검증 결과
  }
}
```

### verification
```
{
  "verification_id": "verify-xxxxxxxx",
  "scan_id": "scan-xxxxxxxx",                  # 어떤 스캔 결과 값인지
  "target_type": "redis",
  "template_id": "redis-unauth-info-check",    # 규칙 파일(yaml)의 id값
  "verification_type": "risk",                 # 어느 규칙 타입인지 (service/risk)
  "method": "nuclei",
  "status": "verified",            # verified(증명완료), suspected(규칙으로 증명 불가. 그러나 다른 근거들로 의심되는 상태), not_verified(증명 실패), error(실행실패)
  "target": "redis-4-unacc.lab.local:6379",
  "matched_port": 6379,
  "evidence": "...",                           # 매칭 근거
  "raw_output": "...",
  "confidence": "high",                        # hight : verified , medium : suspected , low : not_verified 혹은 error
  "reason": "direct nuclei match",
  "matched_analysis_titles": [],               # status=suspected 일 경우에만. suspected가 된 근거
  "created_at": "2026-03-19T..."
}
```

### (ex) 예시
```
{
  "scan_id": "scan-e0017c5d",
  "target_type": "redis",
  "target": "redis-4-unacc.lab.local:6379",
  "results": {
    "service": [
      {
        "verification_id": "verify-b5182696",
        "scan_id": "scan-e0017c5d",
        "target_type": "redis",
        "template_id": "redis-service-check",
        "verification_type": "service",
        "method": "nuclei",
        "status": "verified",
        "target": "redis-4-unacc.lab.local:6379",
        "matched_port": 6379,
        "evidence": "nuclei matched template: redis-service-check, matched_at=redis-4-unacc.lab.local:6379",
        "raw_output": "{...}",
        "confidence": "high",
        "reason": "direct nuclei match",
        "matched_analysis_titles": [],
        "created_at": "2026-03-19T08:31:23.527917+00:00"
      }
    ],
    "risk": [
      {
        "verification_id": "verify-c9cbcca2",
        "scan_id": "scan-e0017c5d",
        "target_type": "redis",
        "template_id": "redis-replication-risk-check",
        "verification_type": "risk",
        "method": "nuclei",
        "status": "suspected",
        "target": "redis-4-unacc.lab.local:6379",
        "matched_port": 6379,
        "evidence": "template executed but no match was returned; promoted to suspected because service was at least suspected and analysis contains related titles: Redis Replication Abuse RCE Risk",
        "raw_output": "",
        "confidence": "medium",
        "reason": "no direct nuclei risk match, but service verification and related analyzer titles exist",        
        "matched_analysis_titles": [
          "Redis Replication Abuse RCE Risk"
        ],
        "created_at": "2026-03-19T08:31:24.195854+00:00"
      }
    ]
  }
}
```

<br></br>

## 3. CLI 실행
```
docker compose exec backend sh -c "python /app/analysis/verify.py --scan-id scan-xxxxxxxx --target-type redis"
```
 * --scan-id : 필수, 증명할 scan ID 값
 * --target-type : 선택, 증명할 타입
