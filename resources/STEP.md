# Virtual FIDO2 Security Key 멀티플랫폼 구현 단계

이 계획은 [`DUPLICATE.md`](./DUPLICATE.md)의 기존 구현 조사와 [`SPEC.md`](./SPEC.md)의 멀티플랫폼 아키텍처 개정 사항을 바탕으로 한다. v1에서 Windows·macOS·Linux를 모두 필수 지원한다. 공통 인증기 코어는 Rust, 데스크톱 UI는 Tauri 2와 React/TypeScript로 만들고 운영체제 장치 계층은 플랫폼별 어댑터와 필요한 네이티브 드라이버로 구현한다.

각 단계는 완료 기준을 충족한 뒤 다음 단계로 진행한다. `SPEC.md`의 Windows 전용 본문은 OS별 사례로 해석하며, 플랫폼 지원은 실제 검증을 통과한 OS·버전·아키텍처 조합으로만 선언한다.

## 진행 원칙

- 물리 USB 없이 운영체제의 FIDO HID 경로에 가상 인증기를 제공하는 것이 제품 목표다.
- Rust가 공통 CTAPHID·CTAP2·credential 로직을 소유한다. 드라이버 API 때문에 필요한 플랫폼 코드는 해당 OS의 권장 네이티브 기술을 사용한다.
- Tauri UI는 공유하되 장치 연결, 키 보관, 권한, 설치·제거와 서명은 OS마다 독립적으로 검증한다.
- 드라이버, entitlement, OS 권한이 준비되지 않은 플랫폼에서는 지원 상태를 거짓으로 표시하지 않고 안전하게 비활성화한다.
- 가상 HID 열거, 브라우저의 FIDO authenticator 발견, WebAuthn 등록·인증은 서로 다른 검증 항목이다.
- 타사 VID/PID, 제조사, AAGUID, 인증서 또는 attestation을 사칭하지 않는다. 하드웨어 인증기와 동등한 보안을 보장한다고 주장하지 않는다.
- `DUPLICATE.md`의 코드는 라이선스와 보안 상태를 확인하기 전까지 참고 자료로만 취급한다.

## 0단계: 범위와 지원 기준선 확정

### 0단계 작업

- v1 필수 OS를 Windows, macOS, Linux로 확정한다. 대상은 각 OS 공급자가 보안 업데이트 중인 데스크톱 버전이며 x64와 ARM64를 지원한다.
- Linux 배포판은 보안 업데이트 중인 Ubuntu LTS를 우선 대상으로 한다. 다른 배포판은 별도 adapter·패키징·브라우저 검증이 통과하기 전까지 보장하지 않는다.
- 브라우저, OS 버전, CPU 아키텍처, 설치 방식, 권한 및 장치 발견 여부를 추적하는 지원 매트릭스를 만든다.
- 하드웨어 보호 키와 OS 보호 저장소를 기본 사용하고, 소프트웨어 키는 보호 차이를 설명한 뒤 사용자 동의를 받은 경우에만 허용한다.
- 공통 코어, UI, 플랫폼 어댑터, 드라이버, 키 저장소 provider의 책임과 API 경계를 문서화한다.
- Rust toolchain과 Tauri 2의 공식 플랫폼 요구사항을 빌드 파이프라인의 기준으로 기록한다.
- 인증기와 드라이버의 외부 의존성, 라이선스, 코드 서명·배포 제한을 조사한다.

### 0단계 완료 기준

- 제품의 필수·비목표와 플랫폼 지원 매트릭스 초안이 명시되어 있다.
- 아직 검증되지 않은 OS 조합은 지원 완료로 표시하지 않는다.
- `SPEC.md`와 저장소 구조가 같은 모듈 경계를 설명한다.

## 1단계: OS별 가상 HID 실현 가능성 검증

### 1단계 작업

- Linux에서 `/dev/uhid`로 가상 FIDO HID를 생성하고 report 입출력을 확인한다. 권한, udev 규칙, 배포 패키지와 최소 지원 커널을 기록한다.
- Windows에서 UdeCx/KMDF 기반 가상 USB/HID 경로를 검증한다. 개발 키트, 관리자 권한, 서명, 설치·제거, 재부팅과 배포 조건을 조사한다.
- macOS에서 CoreHID virtual device API와 필요한 entitlement를 확인한다. entitlement 요청 가능성, 코드 서명, 배포 및 브라우저에서 보이는 장치 여부를 먼저 확인한다.
- 각 OS에서 장치 열거 이후 Chrome/Edge 등 테스트 대상 브라우저가 FIDO authenticator를 발견하고 HID report를 교환하는지 확인한다.
- USB/IP, UdeCx, UHID, CoreHID 등의 경로를 각각 해당 OS 내 구현으로 평가한다. 한 OS용 transport를 다른 OS의 공통 해법으로 가정하지 않는다.
- 장치 API나 배포 권한을 확보할 수 없는 필수 플랫폼·아키텍처는 v1 차단 항목으로 보고한다. 사용자 승인 없이 v1 필수 범위에서 제외하지 않는다.
- 조사 근거는 공식 Linux kernel, Microsoft WDK/UDE/Windows on Arm, Apple CoreHID/entitlement 문서를 우선하고 각 플랫폼·아키텍처의 날짜와 실제 기기 결과를 기록한다.
- Linux x64/ARM64에서 `/dev/uhid` device-node 권한과 udev/package 경로를 확인한다. UHID create/open, input/output, get/set report 및 destroy lifecycle을 검증한다.
- Windows x64/ARM64에서 WDK로 native driver를 빌드하고 서명, 관리자 설치, 제거, 재부팅 후 상태를 확인한다. ARM64 app emulation을 ARM64 kernel driver 지원으로 간주하지 않는다.
- macOS Intel/Apple silicon에서 CoreHID entitlement 발급 가능 여부를 확인하고 개발 서명과 배포 서명의 차이를 기록한다. FIDO descriptor 및 양방향 report 처리로 WebAuthn 경로를 검증한다.
- 모든 후보 조합에서 signed/package된 앱으로 Chrome과 Edge의 FIDO 등록 및 assertion을 검증한다. HID 열거만 성공한 결과는 WebAuthn 통과로 처리하지 않는다.

### 1단계 완료 기준

- 각 필수 OS와 x64/ARM64 조합에 대해 장치 생성부터 browser WebAuthn 등록 및 assertion까지 재현 가능한 결과가 있다.
- 설치 권한, 드라이버·entitlement·서명 필요성, 설치·제거 영향을 기록했다.
- 통과하지 못한 필수 조합은 v1 차단 항목으로 기록한다. 세 OS 및 필수 아키텍처 검증을 모두 통과하기 전에는 v1 지원 완료를 선언하지 않는다.
- 결과 및 공식 근거를 `SPEC.md` 지원 매트릭스에 반영한다.

## 2단계: Rust workspace와 Tauri 데스크톱 골격

### 2단계 작업

- 현재 workspace의 `ghost-fido-core`, `ghost-platform`, 앱 진입점 구조를 유지하며 새 기능을 적절한 crate에 배치한다.
- `apps/desktop`에 Tauri 2 + React + TypeScript 애플리케이션을 추가하고 현재 CLI 진입점은 개발·진단용으로 유지한다.
- UI와 Rust backend 사이의 명령·이벤트 계약을 최소화하고, credential이나 개인 키 원문을 프런트엔드로 전달하지 않는다.
- Linux, Windows, macOS 개발 환경에서 Tauri 의존 라이브러리와 빌드 절차를 문서화한다.
- CI에 공통 Rust lint/build와 OS별 빌드를 추가한다. OS 네이티브 드라이버가 없는 단계에서는 드라이버 기능을 테스트 성공으로 간주하지 않는다.

### 2단계 완료 기준

- Tauri 창이 세 OS의 개발 빌드에서 실행되거나 미지원 개발 환경의 원인이 명확히 기록되어 있다.
- workspace와 UI 계약에 플랫폼별 코드가 공통 인증기 코어로 유입되지 않는다.
- 드라이버 미구현 상태가 사용자와 로그에 분명하게 표시된다.

## 3단계: 플랫폼 추상화와 상태 모델

### 3단계 작업

- `VirtualHidBackend`를 장치 생성·연결·분리, 상태 조회, report 송수신, 오류 보고 계약으로 구체화한다.
- `KeyStore`, `UserVerification`, `PlatformLifecycle` provider 계약을 정의한다.
- 가용 상태를 `Available`, `PermissionRequired`, `DriverMissing`, `EntitlementUnavailable`, `Unsupported`, `Error` 등 UI에 유용한 구분으로 모델링한다.
- 플랫폼 기능 탐지는 실제 capability 결과를 사용한다. OS 이름만으로 TPM, Secure Enclave 또는 특정 권한이 있다고 추정하지 않는다.
- 어댑터 경계를 mock 가능하게 하여 공통 CTAP 코어와 OS transport를 별도로 개발할 수 있게 한다.

### 3단계 완료 기준

- 구현되지 않은 backend는 명시적 unavailable 오류를 반환하고 연결 완료로 표시되지 않는다.
- 플랫폼별 오류를 공통 오류 모델로 변환하되 진단 원인을 보존한다.
- 공통 인증기 crate가 OS 네이티브 API를 직접 참조하지 않는다.

## 4단계: Linux 가상 HID 어댑터

### 4단계 작업

- `/dev/uhid` 이벤트 lifecycle과 FIDO HID descriptor를 Linux adapter에 구현한다.
- report 크기, interrupt 성격의 입력/출력 동작, 연결 해제, 장치 재생성 및 프로세스 비정상 종료 정리를 구현한다.
- 최소 권한으로 장치에 접근하도록 udev/package 규칙을 정하고 권한 변경을 사용자에게 투명하게 알린다.
- 장치 매니저와 HID 탐색 도구에서 장치를 확인한 뒤 브라우저 FIDO 발견 여부를 검증한다.

### 4단계 완료 기준

- 선정한 Linux 배포판에서 설치·연결·분리·재실행이 재현된다.
- 올바른 권한이 없을 때 안전하고 구체적인 오류를 보여준다.
- 해당 배포판과 브라우저 조합이 지원 매트릭스에 기록된다.

## 5단계: Windows 가상 HID 어댑터

### 5단계 작업

- 1단계에서 선택한 경로를 구현한다. UdeCx/KMDF를 선택하면 가상 USB device descriptor, endpoint queue, report 전달, plug-in/out을 구현한다.
- 사용자 모드 Rust 서비스와 드라이버 사이의 IPC/IOCTL 계약, 권한, 메시지 길이 제한과 오류 복구를 정의한다.
- 드라이버 설치, 서명, 업그레이드, 제거, 재부팅 조건과 서명 키 관리 절차를 문서화한다.
- Windows 장치 열거 이후 브라우저가 FIDO authenticator로 인식하는지 검증한다.

### 5단계 완료 기준

- 지원할 Windows 버전에서 가상 FIDO HID가 연결·분리되고 장치 상태가 일치한다.
- 서명된 설치 패키지와 제거 절차가 준비되거나 배포 blocker가 명시되어 있다.
- 커널 드라이버 오류가 앱·코어를 불안정하게 만들지 않는다.

## 6단계: macOS 가상 HID 어댑터

### 6단계 작업

- CoreHID virtual device API 사용 조건과 entitlement 획득 상태를 확인하고 검증된 방식만 선택한다.
- entitlement와 사용자 동의가 없는 환경에서 설치·실행을 가장하지 않는 오류 흐름을 구현한다.
- 코드 서명, notarization, 업데이트, 권한 변경과 제거 시 장치 정리 동작을 검증한다.
- HID 장치 발견과 Chrome/지원 브라우저의 FIDO authenticator 탐색을 별도로 확인한다.

### 6단계 완료 기준

- 배포용 entitlement와 서명을 적용한 환경에서만 지원 상태를 표시한다.
- 지원 macOS 버전·아키텍처의 연결·분리 및 브라우저 상호운용 증거가 있다.
- entitlement가 승인되지 않으면 macOS 배포 범위와 대체 일정이 분명하다.

## 7단계: 공통 CTAPHID 및 CBOR

### 7단계 작업

- HID report 프레이밍, 채널 할당, 초기·후속 패킷, 분할·재조립, 동시 요청과 타임아웃을 구현한다.
- `INIT`, `PING`, `CBOR`, `CANCEL`, `KEEPALIVE`, `ERROR`를 처리한다.
- CBOR 크기·중첩·타입·키 유효성을 검증하고 잘못된 입력을 규격 오류로 변환한다.
- USB I/O를 추상화된 report transport로 전달해 동일한 core를 세 플랫폼이 사용하도록 한다.

### 7단계 완료 기준

- 세 OS backend의 report 교환에 같은 CTAPHID 코어가 사용된다.
- 정상·오류·취소·timeout 메시지 교환이 검증된다.
- 비정상 입력으로 프로세스가 종료되거나 다른 요청 상태가 오염되지 않는다.

## 8단계: CTAP2 인증기와 자격 증명

### 8단계 작업

- 지원할 CTAP 버전과 기능을 확정하고 `GetInfo`를 먼저 구현한다.
- 단계적으로 `MakeCredential`, `GetAssertion`, `ClientPIN`, `Reset`과 필요한 credential management 기능을 구현한다.
- RP ID hash, client data hash 입력, authenticator data, flags, credential ID와 서명을 규격에 맞게 처리한다.
- discoverable credential과 allow list 기반 조회, 삭제, 초기화, 중복 등록 정책을 구현한다.
- 지원하지 않는 확장, 알고리즘과 attestation 정책을 명시하고 과장하지 않는다.

### 8단계 완료 기준

- 공통 CTAP 적합성 검증에서 지원 기능과 오류 응답이 일치한다.
- 다른 RP의 자격 증명이 조회되거나 사용되지 않는다.
- 모든 OS에서 동일한 인증 엔진 동작을 재사용한다.

## 9단계: 키 저장 provider와 데이터 보호

### 9단계 작업

- 플랫폼 키 저장 provider를 구현하고 각 provider가 제공하는 하드웨어 보호, 비추출성, 백업 가능성 및 사용자 확인 수준을 보고한다.
- 개인 키 원문을 SQLite, 설정 파일, 로그 또는 프런트엔드에 기록하지 않는다. 공통 저장소에는 안전한 key reference와 최소 메타데이터만 저장한다.
- TPM, Secure Enclave 또는 OS 보호 저장소의 존재만으로 보안 보장을 추정하지 않고 실제 서명 경로와 정책을 검증한다.
- 하드웨어/OS 보호 키를 기본 사용한다. 키 보호 수준과 exportability를 credential별로 기록·표시하고 software key로 자동 fallback하지 않는다.
- 소프트웨어 키는 사용자에게 위험을 설명하고 명시적으로 동의받은 후 생성하며 해당 키로 만든 credential을 UI에서 계속 식별한다.
- PIN 처리, 실패 횟수, 잠금·재시도와 UV/UP 상태를 확정한다.
- 키 생성 실패, 기기 교체, OS 재설치, 저장소 복구, credential 삭제 및 인증기 초기화의 영향과 데이터 손실을 문서화한다.

### 9단계 완료 기준

- 각 지원 OS에서 선택한 provider의 키 생성·서명·삭제가 검증된다.
- 비지원 보안 기능은 지원 불가로 처리하고, software-key fallback은 위험 고지와 명시적 사용자 동의가 있을 때만 제공한다.
- 개인 키, PIN 원문, 인증 비밀값이 저장소와 로그에서 노출되지 않는다.

## 10단계: 사용자 승인, 서비스 수명주기와 Tauri UI

### 10단계 작업

- RP 정보와 요청 종류를 표시하고 명시적 승인·거부·취소·timeout을 CTAP 요청 수명주기에 연결한다.
- UI에는 OS/backend 상태, 권한·드라이버·entitlement 필요 여부, 키 저장 보호 상태를 정확히 표시한다.
- 설정, PIN, credential 목록과 삭제, 인증기 초기화, 오류 진단 및 종료 전 장치 분리 흐름을 구현한다.
- Tauri command/event 입력 검증, 창 권한, IPC 사용자 세션 검증과 요청 상관관계를 적용한다.
- 로그오프, 앱 종료, 서비스 재시작, 강제 종료 및 업데이트 중 장치 연결 정리와 복구를 구현한다.

### 10단계 완료 기준

- 승인 전에는 서명하지 않으며 취소·timeout 후 해당 요청을 재사용할 수 없다.
- 앱의 연결 상태가 실제 OS backend 상태와 일치한다.
- UI가 보안 보호 수준이나 OS 지원을 오해하게 표현하지 않는다.

## 11단계: 브라우저 및 사이트 상호운용

### 11단계 작업

- 지원 OS마다 동일한 WebAuthn 테스트 RP에서 credential 등록과 인증을 수행한다.
- 각 조합에 대해 장치 열거, 브라우저 FIDO 발견, CTAPHID, CTAP2, 서명 검증, RP 최종 수락을 따로 기록한다.
- Chrome과 Edge를 우선 검증하고 버전, OS 설정, 권한, 테스트 결과를 지원 매트릭스에 기록한다.
- 사용자 승인, PIN/UV, discoverable credential, allow list, 거부, 취소, timeout, 재인증과 초기화 이후 동작을 검증한다.
- 하드웨어 attestation이나 특정 인증 수준을 요구하는 서비스는 제한으로 정확히 기록한다.

### 11단계 완료 기준

- 지원한다고 표시할 각 OS·브라우저 조합에서 자체 RP 등록과 재인증이 성공한다.
- 서버 측 서명 검증 결과와 재현 절차가 보관되어 있다.
- 실패 계층과 사이트별 제한을 구분해서 사용자 문서에 반영한다.

## 12단계: 보안, 안정성 및 호환성 검증

### 12단계 작업

- 프로토콜 파서, 장치 재연결, 권한 부족, 드라이버 오류, entitlement 누락, DB 손상, 키 provider 오류를 검증한다.
- 승인 우회, RP 경계, IPC 호출 권한, credential 삭제, PIN 반복 실패와 로그·크래시 덤프 정보 노출을 점검한다.
- Windows·macOS·Linux 각 지원 환경에서 정상 종료, 강제 종료, 업데이트 실패와 제거 후 장치 상태를 검증한다.
- 공통 코어 검증과 OS별 통합 검증 결과를 별도 보고서로 남긴다.
- 발견 결함을 심각도와 재현 절차로 추적하고 출시 blocker를 해결한다.

### 12단계 완료 기준

- 모든 필수 인수 항목이 통과하거나 미통과 사유와 출시 영향이 승인된 예외로 기록되어 있다.
- 미해결 고위험 보안 결함이 없다.
- OS별 지원 매트릭스에 검증 증거가 연결되어 있다.

## 13단계: 플랫폼별 패키징과 배포

### 13단계 작업

- Windows installer 및 드라이버 패키지, macOS 서명·notarization·entitlement, Linux 배포 패키지와 권한 설치 절차를 각각 구성한다.
- Rust/Tauri 빌드, native dependency, 서명, 업데이트와 제거를 OS별 CI 또는 실제 대상 장비에서 검증한다.
- 업데이트·제거 시 장치 분리, 서비스 종료, 사용자 데이터 보존/삭제, 키 참조 삭제 동작을 확인한다.
- 서드파티 라이선스, 드라이버 배포 권한, 개인정보·로그 정책, 보안 한계와 지원 환경을 배포 문서에 명시한다.

### 13단계 완료 기준

- 지원 OS별 깨끗한 환경에서 설치·실행·연결·분리·업데이트·제거가 재현된다.
- 서명 및 배포 권한을 갖춘 패키지만 정식 배포 대상으로 표시한다.
- 지원하지 않는 플랫폼은 설치 시점과 UI에서 명확하게 구분된다.

## 14단계: v1 완료 판정

### 14단계 작업

- `SPEC.md` 목표 G-001부터 G-015와 아래 지원 매트릭스별 인수 증거를 검토한다.
- 지원 OS 각각에서 설치부터 credential 등록, 재인증, 거부, 종료 복구와 제거를 수행한다.
- 공개 문서에 제한된 사이트 호환성, 소프트웨어 인증기 특성, OS별 보호 수준과 복구 한계를 설명한다.
- 남은 미지원 OS는 로드맵으로 남기고 현재 지원 목록에 포함하지 않는다.

### 14단계 완료 기준

- Windows, macOS, Linux의 보안 업데이트 대상 버전에서 x64와 ARM64 지원 조합을 검증하지 못하면 v1 완료로 표시하지 않는다.
- Linux Ubuntu LTS 매트릭스와 Windows/macOS 공급자 보안 업데이트 매트릭스에서 OS 장치·브라우저·WebAuthn 검증이 모두 통과해야 한다.
- 사용자 승인, 키 보호, 오류 복구, 설치·제거와 서명된 패키징이 지원 플랫폼에서 검증되어 있다.

## 요구사항 추적 요약

| SPEC 목표 | 구현 단계 | 검증 근거 |
| --- | --- | --- |
| G-001, G-002, G-009 | 1, 4, 5, 6 | OS별 가상 장치 열거, 연결·분리, 권한과 설치 검증 |
| G-003 | 7 | 세 플랫폼 transport에서 공통 CTAPHID 왕복 검증 |
| G-004 | 8 | CTAP 명령과 CBOR 오류 응답 검증 |
| G-005, G-012 | 11 | OS·브라우저별 자체 RP 등록, 재인증과 서버 서명 검증 |
| G-006, G-011 | 8, 9 | credential 수명주기와 저장소 보호 검증 |
| G-007 | 9 | 각 provider의 실제 키 생성·서명 보호 수준 검증 |
| G-008, G-010 | 9, 10 | 사용자 승인, PIN/UV 및 거부·timeout 검증 |
| G-013 | 3, 10, 12 | 오류 매핑, 안전한 로그와 복구 검증 |
| G-014 | 8, 9, 10, 12 | 초기화 및 키·credential 삭제 검증 |
| G-015 | 4, 5, 6, 10, 12, 13 | OS별 종료 복구, 제거와 장치 정리 검증 |

## 참고 자료

- [멀티플랫폼 설계 명세](./SPEC.md)
- [기존 구현 조사](./DUPLICATE.md)
- [Rust 플랫폼 지원 등급](https://doc.rust-lang.org/rustc/platform-support.html)
- [Tauri 2 사전 요구사항](https://v2.tauri.app/start/prerequisites/)
- [Linux UHID](https://docs.kernel.org/hid/uhid.html)
- [Windows UDE Client Driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver)
- [Apple CoreHID HIDVirtualDevice](https://developer.apple.com/documentation/corehid/hidvirtualdevice)
- [Apple 가상 HID entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device)
