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

### 실행 방법

Python 가상환경을 활성화한 후 의존성을 설치합니다.

`pip install -r requirements.txt`

테스트를 실행합니다.

`python -m pytest -v`

API 서버를 실행하려면 다음 명령어를 사용합니다.

`uvicorn app.main:app --reload`

### 보안 테스트 예시

Alice의 인증 토큰으로 다른 테넌트의 발주 데이터에 접근을 시도합니다.

```bash
curl -i http://127.0.0.1:8000/orders/202 \
 -H "Authorization: Bearer alice-token"
```

취약한 구현과 수정된 구현의 응답을 비교하여, 인증 여부뿐 아니라 요청한 리소스에 대한 접근 권한도 서버에서 검증해야 한다는 점을 확인합니다.

### 현재 진행 상태

[x] FastAPI 기반 실습 환경 구성
[x] 사용자 및 테넌트별 테스트 데이터 구성
[x] IDOR 취약점 재현을 위한 API 구현
[] 테넌트 단위 접근 제어 적용
[] 수정된 로직에 대한 회귀 테스트 작성
[] 취약점 분석 및 개선 보고서 작성

토큰과 데이터는 테스트 목적으로만 사용하며, 실제 서비스나 외부 시스템을 대상으로 하지 않습니다.
