# security

멀티테넌트 API에서 발생할 수 있는 접근 제어 취약점을 재현하고, 서버 측 인가 검증과 회귀 테스트를 통해 해결 과정을 검증

### 실습 환경

- Language: Python
- Framework: FastAPI
- Testing: Pytest, FastAPI TestClient
- Scope: 로컬 테스트 환경

### 구현 범위

- Bearer 토큰을 이용한 사용자 인증
- 테넌트별 발주 데이터 구성
- IDOR (Insecure Direct Object Reference) 취약점 재현
- API 접근 제어 검증 및 수정
- 보안 회귀 테스트 작성

### 고급 트랙: 대규모 인프라 · 오펜시브 · DFIR · 공급망 (Phase 1–4)

기본 멀티테넌트 실습 위에, 프로덕션 규모의 보안 통제를 4단계로 확장한다. 각 단계는
실행 가능한 산출물과 회귀 테스트를 남긴다 (`python -m pytest -q` → 41 passed).

| Phase | 주제                                            | 산출물                                                | 실행                                                 |
| ----- | ----------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------- |
| 1     | 제로 트러스트 K8s (네트워크 격리 · mTLS · eBPF) | `deploy/kubernetes/**`, `deploy/kubernetes/README.md` | `kubectl apply -k deploy/kubernetes/base`            |
| 2     | 오펜시브: API 퍼징 인프라                       | `fuzz/fuzz_api.py`                                    | `python fuzz/fuzz_api.py 400`                        |
| 3     | DFIR: 감사 로그 위협 헌팅 · 측면 이동 추적      | `dfir/threat_hunt.py`, `dfir/sigma_rules.yml`         | `python dfir/threat_hunt.py dfir/sample_audit.jsonl` |
| 4     | 공급망: SBOM · Cosign 서명 · SLSA 프로베넌스    | `supplychain/`, `.github/workflows/supply-chain.yml`  | `python supplychain/gen_sbom.py > sbom.json`         |

**Phase 1 — 제로 트러스트:** L3/L4 기본 차단(`default-deny` NetworkPolicy) + L7 신원
기반 인가(Istio STRICT mTLS, `deny-all` AuthorizationPolicy) + eBPF 런타임 통제(Tetragon이
워크로드 내 예기치 않은 셸 실행을 커널에서 SIGKILL). 워크로드는 non-root · read-only
rootfs · 모든 capability drop · SA 토큰 비활성.

**Phase 2 — 퍼징:** OpenAPI 스키마 기반 변이 퍼저. 세 가지 오라클 — 5xx 크래시,
교차 테넌트 인가 우회(IDOR/BOLA), SQLi 차분(`/vulnerable` vs `/secure`). 의존성 없이
TestClient로 자가 엔드포인트만 테스트한다. 인가 우회 불변식은 `tests/test_fuzz_invariants.py`로 고정.

**Phase 3 — DFIR:** `app/audit.py`의 JSONL 감사 스트림을 파싱해 단일 출발지의 다중 테넌트
접근(측면 이동), SSRF, 인가 열거 버스트, 신원 피벗을 상관 분석하고 공격자 타임라인을
재구성한다. SIEM 적재용 Sigma 룰 포함.

**Phase 4 — 공급망:** `requirements.txt` → CycloneDX 1.5 SBOM(stdlib만 사용) → 이미지
빌드 → Cosign 키리스 서명 → SBOM/SLSA 프로베넌스 attestation. 소비자측 검증 게이트는
`supplychain/verify.sh`.

### 실행 방법

Python 가상환경을 활성화한 후 의존성을 설치합니다.

```bash
pip install -r requirements.txt
```

테스트를 실행합니다.

```bash
python -m pytest -v
```

API 서버를 실행하려면 다음 명령어를 사용합니다.

```bash
uvicorn app.main:app --reload
```

### 보안 테스트 예시

Alice의 인증 토큰으로 다른 테넌트의 발주 데이터에 접근을 시도합니다.

```bash
curl -i http://127.0.0.1:8000/orders/202 \
  -H "Authorization: Bearer alice-token"
```

취약한 구현과 수정된 구현의 응답을 비교하여, 인증 여부뿐 아니라 요청한 리소스에 대한 접근 권한도 서버에서 검증해야 한다는 점을 확인합니다.

### 현재 진행 상태

- [x] FastAPI 기반 실습 환경 구성
- [x] 사용자 및 테넌트별 테스트 데이터 구성
- [x] IDOR 취약점 재현을 위한 API 구현
- [x] 테넌트 단위 접근 제어 적용
- [x] 수정된 로직에 대한 회귀 테스트 작성
- [x] 취약점 분석 및 개선 보고서 작성
- [x] 고급 트랙 Phase 1–4 구현 (인프라 · 퍼징 · DFIR · 공급망)

토큰과 데이터는 테스트 목적으로만 사용하며, 실제 서비스나 외부 시스템을 대상으로 하지 않습니다.

---

### 우선순위

1. **P0 — 인가 검증의 정확성:** 테넌트 간 데이터 격리, 객체 조회·수정·삭제 권한, 목록 조회 필터링을 검증합니다.
2. **P1 — 보안 회귀 테스트와 CI:** 취약한 구현에서 테스트가 실패하고 수정 후 통과하는지 확인합니다.
3. **P2 — 분석 및 설계 문서:** 위협 모델, 취약점 보고서, 보안 요구사항을 작성합니다.
4. **P3 — 추가 취약점과 자동화:** 인증·세션, SQL Injection, XSS를 학습하고 SAST·SCA를 CI에 연결합니다. 핵심 프로젝트가 완성되기 전에는 도구를 과도하게 늘리지 않습니다.

### 주별 계획: 첫 12주

| 주차 | 학습·구현 과제                                                         | 산출물 및 검증 기준                                                                   |
| ---- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1주  | 기존 코드에서 인증·인가 흐름과 테넌트 필터링을 추적하고 위협 모델 작성 | `docs/threat-model.md`; 보호 자산, 신뢰 경계, 공격 경로, 권한 검증 위치 설명          |
| 2주  | IDOR 및 접근 제어 회귀 테스트 보완                                     | `tests/test_authorization.py`; 교차 테넌트 조회·수정·삭제 거부와 데이터 불변성 검증   |
| 3주  | Python·FastAPI·Pydantic·DB 쿼리 흐름 학습                              | 취약 코드와 안전한 코드 비교 예제 2개; 사용자 입력부터 응답까지 데이터 흐름 설명      |
| 4주  | 취약점 분석 및 개선 보고서 작성                                        | `docs/vulnerability-report.md`; 재현 절차, 원인, 영향, 수정, 검증 및 미검증 범위 기록 |
| 5주  | 인증·인가·JWT·세션 보안 학습                                           | 인증 실패 및 권한 검증 테스트; 토큰 유효성과 리소스 접근 권한의 차이 설명             |
| 6주  | SQL Injection 및 XSS 기본 실습                                         | 취약 코드 → 수정 코드 → 회귀 테스트 2~3세트                                           |
| 7주  | Bandit 또는 Semgrep 중 하나와 pip-audit 또는 Dependabot 도입           | 설정 파일, 탐지 사례, 오탐 검토 및 도구의 한계 문서화                                 |
| 8주  | GitHub Actions에 테스트·정적 분석·의존성 검사 연결                     | `.github/workflows/security.yml`; 실패 조건을 탐지하고 수정 후 통과하는 CI 실행 증거  |
| 9주  | 공개 Python 웹 앱을 대상으로 허가된 범위의 보안 코드 리뷰              | 리뷰 보고서와 재현 테스트 또는 근거가 있는 이슈; 추측을 취약점으로 단정하지 않기      |
| 10주 | 위협 모델링 및 보안 요구사항 정의                                      | `docs/security-requirements.md`; 위협, 완화책, 검증 방법을 연결                       |

### 첫 프로젝트의 검증 기준

- Alice가 자신의 테넌트 리소스에 접근할 수 있습니다.
- Alice가 다른 테넌트 리소스를 조회·수정·삭제할 수 없습니다.
- 무단 수정·삭제 요청 이후 데이터가 변경되지 않습니다.
- 목록 조회에서도 다른 테넌트 데이터가 노출되지 않습니다.
- 인증 실패와 인가 실패를 구분하고 정책에 맞는 응답을 반환합니다.
- 클라이언트가 전달한 `tenant_id`만 바꿔 권한을 우회할 수 없습니다.
- 취약한 구현에서 해당 테스트가 실패하고, 수정된 구현에서는 통과합니다.
- 보고서에 실제로 확인한 사항과 검증하지 못한 사항을 구분해 기록합니다.

응답 코드는 프로젝트의 보안 정책에 따라 401, 403 또는 404를 사용할 수 있습니다. 핵심은 비인가 접근이 거부되고 데이터가 노출되거나 변경되지 않는 것입니다.

### 4~6개월 차 심화 계획

| 기간    | 과제                              | 완료 기준                                     |
| ------- | --------------------------------- | --------------------------------------------- |
| 13~14주 | 객체 속성 및 기능 수준 인가 검증  | 역할별 권한 매트릭스와 회귀 테스트            |
| 15~16주 | 로컬 대상 DAST 및 API 보안 테스트 | 검사 범위, 결과, 오탐 및 미탐 한계 기록       |
| 17~18주 | 취약점 관리 프로세스              | 심각도·영향·수정 우선순위·재검증 절차 문서화  |
| 19~20주 | 두 번째 프로젝트 보강             | 코드 리뷰 결과를 수정 또는 회귀 테스트와 연결 |

핵심 프로젝트가 완성되면 심화 학습이 모두 끝날 때까지 기다리지 않고 지원을 시작합니다. DAST 등 보안 검사는 로컬 또는 명시적으로 허가된 대상에 한해 수행합니다.

### 학습 자료

- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [OWASP Application Security Verification Standard (ASVS)](https://asvs.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### 첫 번째 마일스톤

**2주 안에 현재 저장소의 인가 검증과 회귀 테스트를 완성합니다.**

1. 인증·인가 검증 위치와 테넌트 필터링 경로를 추적합니다.
2. 현재 테스트의 커버리지와 미검증 영역을 기록합니다.
3. 교차 테넌트 조회·수정·삭제 테스트를 보완합니다.
4. 무단 요청 이후 데이터 불변성을 확인합니다.
5. 취약점 분석 보고서를 작성합니다.

> **범위 고지:** 이 저장소는 로컬 학습 및 테스트 목적입니다. 실제 서비스나 외부 시스템을 대상으로 무단 테스트를 수행하지 않습니다.
