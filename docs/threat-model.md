# Threat Model: Multi-Tenant API Access Control

## 1. 개요

본 문서는 FastAPI 기반 멀티테넌트 API 서버에서 발생할 수 있는 인가(Authorization) 취약점 및 IDOR(Insecure Direct Object Reference) 위협에 대한 모델링 결과와 방어 전략을 정의한다.

## 2. 보호 자산 (Assets)

- **테넌트별 발주 데이터 (Orders):** 각 기업(Tenant) 고유의 비즈니스 자산으로, 타 테넌트에 노출되거나 변조되어서는 안 된다.

## 3. 신뢰 경계 (Trust Boundaries)

1. **Client vs API Server:** 클라이언트가 전송하는 HTTP 요청(Headers, Path Parameters)은 신뢰할 수 없는 영역이다.
2. **Authentication vs Authorization:** 인증된 사용자(Authenticated User)라 하더라도 모든 리소스에 대한 접근 권한을 자동으로 갖지 않는다.

## 4. 위협 분석 (Threats & Attack Vectors)

- **IDOR (OWASP API1:2023 - Broken Object Level Authorization):**
  - **공격 시나리오:** `tenant-a` 소속의 사용자(Alice)가 합법적인 토큰을 소지한 채, URL 경로의 `order_id`를 임의로 변경하여 `tenant-b`의 자산에 접근을 시도한다.
  - **식별된 위험:** 서버가 요청된 `order_id`의 소유 테넌트를 검증하지 않고 객체 조회만 수행할 경우 교차 테넌트 데이터 유출 발생.

## 5. 완화책 및 보안 요구사항 (Mitigations)

- **서버 측 테넌트 바인딩:** 클라이언트가 전달한 ID 외에, 서버 세션(Bearer 토큰)에서 검증된 `tenant_id`를 데이터 조회 쿼리의 필수 조건으로 강제 주입한다.
- **오류 응답 표준화:** 권한이 없거나 리소스가 존재하지 않는 경우 동일하게 `404 Not Found`를 반환하여 리소스 존재 여부 추정(Enumeration) 공격을 방지한다.
