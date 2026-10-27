# Virtual FIDO2 Security Key

> 물리 USB 없이 동작하는 소프트웨어 기반 가상 USB 보안 키 시스템 설계 명세서

**문서 버전:** 1.0  
**작성 기준일:** 2026-10-26  
**프로젝트 유형:** Windows Desktop Application / Virtual USB Device / FIDO2
Authenticator  
**목표 플랫폼:** Windows 11 x64  
**개발 상태:** 설계 단계

---

## 1. 프로젝트 개요

### 1.1 프로젝트 정의

Virtual FIDO2 Security Key는 **별도의 물리적 USB 장치 없이, 프로그램 실행만으로 Windows에 가상 USB
FIDO2 보안 키를 생성하는 소프트웨어**다.

사용자가 프로그램을 실행하고 가상 보안 키를 활성화하면 운영체제는 USB HID 인증 장치가 연결된 것처럼 인식한다.

Chrome, Edge 등의 브라우저 및 Windows의 WebAuthn 인터페이스를 통해 전달되는 인증 요청은 가상 USB 계층을 거쳐
소프트웨어 FIDO2 인증 엔진으로 전달된다.

인증 엔진은 사용자의 승인을 받은 후 보호된 개인 키로 암호학적 서명을 생성하고, 표준 FIDO2 응답을 반환한다.

사용자는 이를 활용하여 지원되는 웹사이트에 패스키 또는 FIDO2 보안 키를 등록하고 로그인할 수 있어야 한다.

프로젝트는 하드웨어 보안 키의 기능적 동작을 소프트웨어로 구현하는 것이 목적이며, 물리적 보안 칩을 갖춘 인증기와 동일한 보안 수준을 보장한다고
주장하지 않는다.

### 1.2 핵심 원칙

1. 물리 USB 장치가 필요 없어야 한다.
2. 일반 USB 메모리를 개조하거나 포맷할 필요가 없어야 한다.
3. 프로그램 내부에서 가상 USB 장치를 생성해야 한다.
4. Windows가 해당 장치를 USB HID 장치로 열거할 수 있어야 한다.
5. 표준 FIDO2 / CTAP2 인증 요청을 처리해야 한다.
6. WebAuthn 호환 브라우저에서 인증에 사용할 수 있어야 한다.
7. 인증용 개인 키는 외부에 노출하지 않아야 한다.
8. 가능한 경우 TPM 2.0 기반 비추출형 개인 키를 사용해야 한다.
9. 사용자의 명시적 승인 없이 인증을 완료해서는 안 된다.
10. 프로그램 종료 시 가상 USB 장치를 연결 해제해야 한다.
11. 인증 정보의 기밀성, 무결성 및 장치 수명주기를 관리해야 한다.
12. 사용자에게 실제 하드웨어 인증기라는 허위 보안 보증을 제공해서는 안 된다.

## 2. 프로젝트 탄생 배경과 결정 과정

### 2.1 최초 아이디어: 일반 USB 개조

최초 구상은 일반 USB 메모리의 기존 저장 시스템을 제거하고 보안 키 전용 시스템을 새로 설치하는 것이었다.

일반 USB 메모리는 대부분 USB Mass Storage 장치로 동작한다.

일반적인 USB 포맷이나 파일 시스템 교체만으로 FIDO2 장치로 전환할 수 없으며, 컨트롤러 펌웨어를 임의로 변경할 수도 없다.

이 때문에 해당 방식을 최종 구현 경로에서 제외한다.

### 2.2 웹사이트 인증 요구사항 확인

프로젝트는 다음과 같은 사용자 흐름을 지원해야 한다.

- 패스키 추가
- 호환되는 FIDO 보안 키 추가
- 인증 수단 등록
- 복구 코드 저장 안내
- 등록 완료 확인

이 과정에서 웹사이트가 외부 USB 보안 키를 사용하도록 요청하는 경우가 있다.

따라서 단순한 인증 정보 저장 프로그램이나 웹 브라우저용 패스키 관리 기능만으로는 목표를 충족하지 못한다.

특히 웹사이트가 USB 보안 키 경로를 요구하는 상황에서도 동작할 수 있도록 운영체제 수준의 장치 에뮬레이션이 필요하다.

단, 웹사이트가 물리적 하드웨어의 존재, 특정 인증기 인증서 또는 FIDO 인증 상태까지 검증한다면 소프트웨어 에뮬레이터는 거부될 수 있다.

### 2.3 소프트웨어 기반 인증기로 방향 변경

이후 프로그램 실행 시 가상의 USB 기기가 연결되었다고 운영체제가 인식하도록 하는 구조가 제안되었다.

프로그램은 인증 정보를 안전하게 관리하고, 개인 키로 서명을 수행한 결과만 전달한다.

이를 통해 일반적인 USB 메모리보다 유연하고, 물리적 장치가 없어도 작동하는 인증기를 구현하고자 한다.

### 2.4 개인 키 보호 요구사항 추가

초기 보안 구상은 인증 정보를 비공개로 암호화하고 복호화하지 못하게 만드는 것이었다.

이 요구사항의 실질적 목적은 개인 키의 추출과 노출을 방지하는 것이다.

일반적인 암호화 저장소에서는 키 사용 시 복호화가 필요할 수 있으므로 모든 상황에서 복호화를 금지한다고 정의하는 것은 부정확하다.

따라서 최종 보안 목표를 다음과 같이 구체화한다.

- 개인 키를 평문 파일로 저장하지 않는다.
- 가능한 경우 비추출형 키로 생성한다.
- TPM 내부에서 서명을 수행한다.
- 키가 외부 프로그램이나 로그에 노출되지 않도록 한다.
- TPM을 사용할 수 없는 경우 별도 보안 정책을 적용한다.

### 2.5 USB 에뮬레이션을 v1 필수 요구사항으로 확정

Windows WebAuthn Plugin API를 활용하는 소프트웨어 인증기 방식도 검토하였다.

그러나 해당 방식만으로는 실제 USB 장치 열거가 필요한 인증 경로를 보장할 수 없다.

따라서 USB 에뮬레이션을 추후 확장 기능이 아닌 최초 구현 범위에 포함한다.

### 2.6 물리 USB 장치의 완전 배제

최종적으로 다음 사항을 명확히 확정한다.

**사용자는 어떤 종류의 외장 USB 메모리나 하드웨어 보안 키도 연결하지 않는다.**

프로그램과 필요한 가상 장치 드라이버를 설치하는 것만으로 사용할 수 있어야 한다.

## 3. 목표와 비목표

### 3.1 필수 목표

| ID | 목표 | 우선순위 |
| --- | --- | --- |
| G-001 | 물리 USB 없는 가상 USB 장치 생성 | 필수 |
| G-002 | Windows USB HID 장치 열거 | 필수 |
| G-003 | FIDO CTAPHID 통신 지원 | 필수 |
| G-004 | CTAP2 인증기 구현 | 필수 |
| G-005 | WebAuthn 등록 및 인증 | 필수 |
| G-006 | 패스키 자격 증명 관리 | 필수 |
| G-007 | TPM 2.0 보호 키 연동 | 필수 목표 |
| G-008 | 사용자 승인 인터페이스 | 필수 |
| G-009 | 가상 USB 연결 및 분리 | 필수 |
| G-010 | PIN 설정 및 검증 | 필수 |
| G-011 | 암호화된 메타데이터 저장 | 필수 |
| G-012 | 브라우저 호환성 테스트 | 필수 |
| G-013 | 오류 및 감사 로그 | 필수 |
| G-014 | 인증기 초기화 기능 | 필수 |
| G-015 | 안전한 프로그램 종료 및 복구 | 필수 |

### 3.2 비목표

v1에서는 다음을 필수 지원하지 않는다.

- 물리적 USB 보안 키 제작
- 실제 USB 컨트롤러 펌웨어 교체
- BLE/NFC 보안 키
- macOS/Linux 네이티브 지원
- 서로 다른 PC 사이의 자동 패스키 동기화
- 클라우드 인증 정보 저장
- 타사 보안 키의 개인 키 추출
- 모든 웹사이트와의 무조건적인 호환
- 하드웨어 FIDO 인증기 인증 수준 보장
- 타사 인증기의 제조사 신원 위장

## 4. 개발 환경 및 기술 스택

### 4.1 대상 환경

| 항목 | 권장 환경 |
| --- | --- |
| OS | Windows 11 64-bit |
| UI | C# / .NET 8 이상 |
| 관리 서비스 | C# / .NET |
| 인증 엔진 | C# / .NET |
| USB/IP 에뮬레이션 | USB/IP 프로토콜 기반 |
| 가상 USB 컨트롤러 | VHCI 호환 드라이버 |
| 정식 드라이버 대안 | Windows UdeCx / KMDF |
| 암호화 | Windows CNG |
| 키 보관 | TPM 2.0 |
| 인증 승인 | 프로그램 UI / Windows Hello 연동 검토 |
| 메타데이터 저장 | SQLite |
| 통신 직렬화 | CBOR |
| 진단 및 테스트 | .NET Test / Windows SDK / WebAuthn 테스트 환경 |

선정된 기술은 초기 권장안이며, 드라이버 호환성 및 라이선스 검토 결과에 따라 세부 구현을 변경할 수 있다.

### 4.2 주요 프로토콜

- USB Device Emulation
- USB Human Interface Device (HID)
- USB/IP
- CTAPHID
- CTAP2
- WebAuthn
- CBOR
- TPM 2.0
- Windows CNG

FIDO2 구현은 등록 요청과 인증 요청뿐 아니라 장치 정보, PIN, 사용자 확인, 자격 증명 관리 및 프로토콜 오류 처리를 포함해야 한다.

## 5. 시스템 전체 아키텍처

### 5.1 논리 구성

```text
┌──────────────────────────────────┐
│          Website / RP            │
│      Passkey / Security Key      │
└────────────────┬─────────────────┘
                 │ WebAuthn
                 ▼
┌──────────────────────────────────┐
│        Browser / Windows         │
│       WebAuthn Client Stack      │
└────────────────┬─────────────────┘
                 │ FIDO USB HID
                 ▼
┌──────────────────────────────────┐
│       Virtual USB Controller     │
│          USB/IP / VHCI           │
│                                  │
│    Windows Device Enumeration    │
└────────────────┬─────────────────┘
                 │ HID Reports
                 ▼
┌──────────────────────────────────┐
│         Virtual USB Layer        │
│                                  │
│  Descriptor / Endpoints / Queue  │
│  Connect / Disconnect / Events   │
└────────────────┬─────────────────┘
                 │ CTAPHID
                 ▼
┌──────────────────────────────────┐
│         CTAP Transport           │
│                                  │
│    INIT / PING / CBOR / CANCEL   │
│    Message Framing / Channels    │
└────────────────┬─────────────────┘
                 │ CTAP2 / CBOR
                 ▼
┌──────────────────────────────────┐
│        FIDO2 Authenticator       │
│                                  │
│   MakeCredential / GetAssertion  │
│   GetInfo / ClientPIN / Reset    │
│   Credential Management          │
└─────────┬──────────────┬─────────┘
          │              │
          ▼              ▼
┌────────────────┐ ┌────────────────┐
│ User Presence  │ │ Credential     │
│ & Verification │ │ Storage        │
│                │ │                │
│ PIN / Approval │ │ SQLite / CNG   │
│ Windows Hello  │ │ TPM Metadata   │
└────────────────┘ └───────┬────────┘
                           │ Sign
                           ▼
                  ┌────────────────┐
                  │   TPM 2.0      │
                  │ Non-exportable │
                  │ Private Keys   │
                  └────────────────┘
```

**이 구성에는 실제 USB 장치가 존재하지 않는다.**

가상 USB 컨트롤러 및 장치의 연결 상태만 운영체제 내부에서 생성된다.

### 5.2 모듈 분리 원칙

각 모듈은 독립 인터페이스를 통해 연결한다.

가상 USB 구현을 USB/IP에서 UdeCx로 변경하더라도 FIDO2 인증 엔진과 키 저장소를 재작성하지 않아야 한다.

또한 인증 엔진에 실제 USB 디바이스 또는 물리 포트에 대한 의존성을 직접 두지 않는다.

## 6. Virtual USB Layer

### 6.1 목적

운영체제와 브라우저에 FIDO 호환 USB HID 장치를 노출한다.

단순한 가상 파일 시스템이나 이동식 디스크가 아니라 USB 장치로 열거되어야 한다.

### 6.2 USB 장치 속성

초기 설계값은 다음과 같다.

| 항목 | 값 |
| --- | --- |
| 장치 유형 | USB HID |
| Interface Class | 0x03 |
| Interface Subclass | 0x00 |
| Interface Protocol | 0x00 |
| FIDO Usage Page | 0xF1D0 |
| FIDO CTAPHID Usage | 0x01 |
| 전송 | Interrupt IN / OUT |
| 일반적 HID 보고서 크기 | 64 bytes |
| 장치 수명주기 | 소프트웨어 관리 |

VID/PID는 정당하게 사용할 수 있는 식별자 정책을 별도로 결정하며, 상용 보안 키 제조사의 식별자를 임의로 사칭하지 않는다.

### 6.3 가상 장치 연결

프로그램이 가상 보안 키 활성화를 요청하면 다음을 실행한다.

1. 사용자 세션과 프로그램 상태를 확인한다.
2. 인증 엔진을 초기화한다.
3. 안전한 저장소에 접근 가능한지 확인한다.
4. USB/IP 서비스 또는 드라이버 인터페이스를 초기화한다.
5. 가상 USB 장치를 연결한다.
6. Windows의 장치 열거 완료를 확인한다.
7. FIDO HID 인터페이스가 발견되는지 확인한다.
8. 성공 시 연결 상태를 UI에 표시한다.

단계 중 하나가 실패하면 가상 장치를 남기지 않고 롤백한다.

### 6.4 가상 장치 분리

사용자가 연결 해제를 누르거나 프로그램이 정상 종료되면 다음 동작을 수행한다.

1. 새로운 인증 요청의 접수를 중단한다.
2. 진행 중인 요청을 취소하거나 안전하게 종료한다.
3. 요청별 민감 데이터를 정리한다.
4. USB/IP 통신을 종료한다.
5. 가상 USB 장치를 분리한다.
6. Windows가 연결 해제를 반영했는지 확인한다.
7. 프로그램 상태를 비활성으로 변경한다.

프로세스 비정상 종료, 강제 종료, 시스템 재시작이 발생한 경우에도 별도 관리 서비스가 잔여 장치 상태를 정리할 수 있어야 한다.

### 6.5 USB/IP 및 VHCI 방식

v1의 우선 구현 경로로 USB/IP + VHCI를 검토한다.

구조는 다음과 같다.

```text
Virtual FIDO Application
         |
         | Loopback Communication
         v
Local USB/IP Server
         |
         | Virtual USB Transfers
         v
VHCI Kernel Driver
         |
         v
Windows USB HID Stack
         |
         v
Windows FIDO Client
```

원격 네트워크 연결은 v1에서 필요하지 않다.

가능한 한 모든 USB/IP 통신을 로컬 컴퓨터 내부로 제한한다.

로컬 서버는 일반 네트워크 인터페이스에 노출하지 않아야 하며, 승인되지 않은 프로세스의 접근을 통제해야 한다.

### 6.6 UdeCx 대안

Windows UdeCx는 가상 USB 호스트 컨트롤러와 가상 USB 장치를 구현하기 위한 Microsoft의 드라이버 구조다.

USB/IP 방식이 장기 유지보수, 드라이버 배포 또는 보안 요구사항을 만족하지 못한다면 UdeCx 기반 자체 KMDF 드라이버를 구현할 수
있다.

다만 이 방식은 Windows 커널 드라이버 개발과 서명 및 배포 작업을 추가로 요구한다.

### 6.7 연결 상태

장치 상태는 다음과 같이 구분한다.

```text
UNINITIALIZED
      |
      v
INITIALIZING
      |
      v
READY
      |
      v
CONNECTING
      |
      v
CONNECTED
      |
      +----> AUTHENTICATING
      |             |
      |             v
      |         CONNECTED
      |
      v
DISCONNECTING
      |
      v
READY

Any State -> ERROR
ERROR -> RECOVERING -> READY
```

사용자가 인증기를 잠갔을 때와 USB 장치를 분리했을 때를 별개의 상태로 취급한다.

## 7. CTAPHID 프로토콜 엔진

### 7.1 역할

USB HID 전송 계층과 FIDO2 명령 처리 계층 사이의 통신을 담당한다.

CTAPHID는 메시지 분할, 조립, 채널 관리, 오류 처리를 수행한다.

### 7.2 지원 명령

| 명령 | v1 처리 |
| --- | --- |
| CTAPHID_INIT | 필수 |
| CTAPHID_PING | 필수 |
| CTAPHID_CBOR | 필수 |
| CTAPHID_CANCEL | 필수 |
| CTAPHID_ERROR | 필수 |
| CTAPHID_KEEPALIVE | 필수 |
| CTAPHID_MSG | CTAP1 지원 여부에 따라 결정 |
| CTAPHID_LOCK | 호환성 요구에 따라 구현 |
| CTAPHID_WINK | 선택 |

### 7.3 메시지 처리

CTAPHID 엔진은 다음 기능을 제공한다.

- 초기 메시지 수신
- 연속 메시지 수신
- 메시지 재조립
- 채널 식별
- 요청 취소
- 타임아웃
- 비정상 메시지 거부
- 동시 채널 요청 처리
- 인증 처리 중 Keepalive 전송
- 응답 메시지 분할

잘못된 길이, 순서, 채널 및 명령이 전달되어도 프로그램이 충돌하거나 메모리를 침범하지 않아야 한다.

## 8. CTAP2 인증 엔진

### 8.1 핵심 목적

웹사이트에서 요청하는 자격 증명 생성, 공개 키 등록, 사용자 확인 및 로그인용 서명을 수행한다.

### 8.2 구현 명령

#### authenticatorGetInfo

인증기의 기능과 지원 범위를 반환한다.

반환 정보에는 다음이 포함된다.

- 지원 CTAP 버전
- AAGUID
- 지원 확장 기능
- 지원 옵션
- PIN 프로토콜
- 인증기가 지원하는 최대 메시지 크기
- 지원 알고리즘
- 자격 증명 관리 지원 여부

실제로 구현하지 않은 기능을 지원한다고 광고해서는 안 된다.

#### authenticatorMakeCredential

새로운 패스키를 생성한다.

처리 절차:

1. 웹사이트의 등록 요청 수신
2. rpId 및 요청 정보 검증
3. 사용자 존재 및 확인 요구사항 검사
4. 사용자 승인 요청
5. 새 비대칭 키 쌍 생성
6. 개인 키를 보호 저장소에 연결
7. 공개 키 및 Credential ID 생성
8. 인증기 데이터와 Attestation 응답 구성
9. 결과 반환
10. 등록 성공 확인 후 저장 상태 갱신

가능한 경우 ES256을 우선 지원한다.

Attestation은 실제 하드웨어 인증기라는 허위 주장을 하지 않는 방식으로 제공한다.

#### authenticatorGetAssertion

기존 자격 증명으로 서명한다.

처리 절차:

1. 로그인 요청 수신
2. rpId 및 Credential ID 일치 여부 검사
3. 관련 자격 증명 탐색
4. 사용자 존재 및 확인 정책 검사
5. 사용자 승인 요청
6. 인증 데이터 구성
7. 보호된 개인 키로 서명
8. Signature 및 Credential 정보 반환
9. 인증 결과에 따른 상태 갱신

#### authenticatorClientPIN

PIN 등록, 확인 및 PIN 기반 사용자 검증을 수행한다.

PIN은 평문으로 저장하지 않는다.

표준 PIN 프로토콜에 따라 키 교환 및 인증 토큰을 처리한다.

잘못된 PIN 시도에 대한 횟수 제한과 잠금 정책을 제공한다.

#### authenticatorReset

인증기 초기화를 수행한다.

초기화 시 다음을 처리한다.

- 모든 자격 증명 삭제
- 인증기 내부 암호화 비밀 폐기
- PIN 상태 초기화
- 관련 메타데이터 삭제
- TPM 키 폐기 요청
- 초기화 결과 확인

초기화는 사용자에게 명확하게 경고하고 별도의 확인 절차를 거쳐야 한다.

#### Credential Management

등록된 패스키를 조회하고 삭제할 수 있어야 한다.

단, Windows 앱에서 직접 수행하는 관리 기능과 CTAP 표준을 통해 제공하는 Credential Management 기능을 별도로
구현하고 검증한다.

## 9. 패스키 및 자격 증명 관리

### 9.1 자격 증명 구조

각 자격 증명은 다음 정보를 논리적으로 관리한다.

```text
Credential
 ├─ credentialId
 ├─ rpId
 ├─ userHandle
 ├─ userName
 ├─ displayName
 ├─ publicKey
 ├─ privateKeyReference
 ├─ algorithm
 ├─ createdAt
 ├─ lastUsedAt
 ├─ signCount
 ├─ discoverable
 ├─ credProtectPolicy
 └─ status
```

privateKeyReference는 실제 개인 키가 아니라 TPM 또는 키 저장소의 키 식별자를 의미한다.

### 9.2 저장 정책

- Credential ID는 고유해야 한다.
- RP별 자격 증명을 분리한다.
- 개인 키를 SQLite에 평문으로 저장하지 않는다.
- 계정 정보 및 민감한 메타데이터를 암호화한다.
- 자격 증명 삭제와 TPM 키 삭제의 정합성을 유지한다.
- 손상된 데이터베이스는 인증 엔진에 직접 전달하지 않는다.
- 파일 변조 및 데이터 무결성 검증 기능을 제공한다.

### 9.3 패스키 관리 인터페이스

사용자는 프로그램에서 다음 정보를 확인할 수 있다.

- 등록된 사이트
- 계정 이름
- 생성 날짜
- 마지막 사용 날짜
- 키 저장 방식
- 사용 가능 여부

개인 키 원문은 표시하거나 일반적인 내보내기 기능으로 추출할 수 없어야 한다.

## 10. 암호화 및 개인 키 보호

### 10.1 핵심 보안 요구사항

프로젝트의 최우선 보안 원칙은 **개인 키가 외부로 노출되지 않은 상태에서 인증 서명만 수행하는 것**이다.

### 10.2 TPM 2.0 기반 키 보호

TPM 사용이 가능한 시스템에서는 다음 절차를 따른다.

1. TPM 사용 가능 여부 확인
2. 비추출형 비대칭 키 생성
3. 공개 키 확보
4. 키 식별자 저장
5. 서명이 필요할 때 TPM에 서명 요청
6. 서명 결과만 반환

개인 키 원문을 파일에 저장하거나 프로그램에서 직접 직렬화하지 않는다.

TPM 내 키를 비추출형으로 생성하는 것은 키 유출 위험을 줄이지만, 악성 프로그램이 현재 사용자 권한을 악용해 서명을 요청하는 위험까지 완전히
제거하지는 못한다.

### 10.3 암호화 저장소

SQLite에 저장되는 메타데이터와 소프트웨어 키 저장이 필요한 정보는 별도의 암호화 계층으로 보호한다.

사용 가능한 기술은 다음과 같다.

- Windows CNG
- Windows DPAPI
- AES-256-GCM
- TPM 기반 키 래핑

암호화 알고리즘은 인증된 암호화 방식을 사용해야 한다.

암호화 키 관리와 데이터 암호화를 분리하고, 암호화 데이터에는 버전 및 무결성 검증 정보를 포함한다.

### 10.4 TPM 미지원 환경

TPM을 사용할 수 없는 경우 두 가지 운영 정책을 검토한다.

#### Strict Mode

- TPM을 필수로 요구한다.
- 비추출형 키를 생성하지 못하면 인증기 초기화를 거부한다.
- 높은 보안 요구사항이 있는 기본 권장 모드다.

#### Software Fallback Mode

- 암호화된 소프트웨어 키를 사용한다.
- 별도의 사용자 승인과 명시적 위험 고지가 필요하다.
- 하드웨어 기반 비추출 보장을 제공하지 않는다.
- v1에 포함할지 여부는 보안 검토 후 확정한다.

### 10.5 메모리 보호

- 개인 키의 불필요한 메모리 복사를 금지한다.
- 민감한 버퍼의 수명을 최소화한다.
- 사용이 끝난 민감한 버퍼는 가능한 범위에서 안전하게 정리한다.
- PIN을 로그에 기록하지 않는다.
- 크래시 덤프에 민감 정보가 남지 않도록 설정한다.
- 디버그 빌드와 운영 빌드의 보안 정책을 분리한다.

### 10.6 복구 정책

TPM 비추출형 키는 일반적인 백업 파일로 복원할 수 없다.

따라서 복구 방식을 명확히 구분한다.

- 웹사이트에서 발급한 복구 코드는 해당 웹사이트의 계정 복구 수단이다.
- 복구 코드만으로 손실된 FIDO2 개인 키를 복구할 수는 없다.
- 인증기 초기화 또는 TPM 손실 시 기존 패스키를 잃을 수 있다.
- 계정 복구 코드는 별도의 암호화된 저장소에 보관하도록 안내한다.
- 인증기 삭제 전에 다른 인증 수단을 등록하도록 경고한다.

v1에서는 TPM 개인 키를 일반 파일 형태로 내보내는 기능을 제공하지 않는다.

## 11. 사용자 존재 및 사용자 확인

### 11.1 사용자 존재(User Presence)

실제 하드웨어 보안 키의 터치 동작을 소프트웨어 승인 인터페이스로 대체한다.

인증 요청이 들어오면 사용자가 직접 승인해야 한다.

승인 화면에는 다음 정보를 제공한다.

- 요청을 발생시킨 사이트 식별 정보
- 등록 또는 로그인 요청의 구분
- 관련 계정 정보
- 승인 버튼
- 거부 버튼
- 요청 제한 시간

### 11.2 사용자 확인(User Verification)

사용자 확인을 위해 다음 기능을 고려한다.

- FIDO PIN
- Windows Hello 연동
- 추가적인 애플리케이션 잠금

Windows Hello를 사용할 경우 실제 구현이 CTAP의 UV 요구사항을 충족하는지 별도 검증한다.

단순히 앱 잠금을 해제했다는 이유만으로 CTAP 사용자 확인이 완료된 것으로 표시해서는 안 된다.

### 11.3 승인 보안 정책

- 승인 요청은 제한 시간 후 만료된다.
- 승인하지 않은 요청은 자동 성공 처리되지 않는다.
- 백그라운드 상태에서 무조건적인 자동 인증을 수행하지 않는다.
- 요청별 승인 토큰은 한 번만 사용한다.
- 사용자 확인 완료 상태는 영구 유지하지 않는다.
- 프로그램이 잠긴 상태에서는 새로운 인증에 사용할 수 없다.
- Windows 로그인 세션 변경 시 진행 중인 민감한 인증을 취소한다.

## 12. 데스크톱 프로그램 UI

### 12.1 메인 화면

메인 화면에는 다음 구성 요소를 제공한다.

```text
┌─────────────────────────────────────┐
│ Virtual FIDO2 Security Key          │
├─────────────────────────────────────┤
│                                     │
│ Security Key Status                 │
│                                     │
│ ● Disconnected                      │
│                                     │
│ [ Connect Virtual USB ]             │
│                                     │
│ TPM: Available                      │
│ Credentials: 0                      │
│ Security Mode: Strict               │
│                                     │
├─────────────────────────────────────┤
│ Credentials                         │
│ Settings                            │
│ Activity                            │
│ Security                            │
└─────────────────────────────────────┘
```

### 12.2 연결 상태 UI

사용자에게 다음 상태를 명확히 표시한다.

- Disconnected
- Initializing
- Connecting
- Connected
- Authentication Pending
- Locked
- Error
- Recovering

Connected 상태에는 Windows 장치 인식 여부를 별도로 확인하여 표시한다.

앱 내부 상태가 Connected여도 Windows 장치 열거가 실패했다면 정상 연결이라고 표시하지 않는다.

### 12.3 인증 승인 창

```text
┌─────────────────────────────────────┐
│ Security Key Authentication         │
├─────────────────────────────────────┤
│                                     │
│ Authentication request received     │
│                                     │
│ Website: example.com                │
│ Action: Sign in                     │
│ Account: user@example.com           │
│                                     │
│ Confirm this authentication?        │
│                                     │
│ [ Deny ]             [ Approve ]    │
│                                     │
└─────────────────────────────────────┘
```

웹사이트 식별 정보는 프로토콜을 통해 확인 가능한 범위로 제한한다.

인증기의 RP ID와 브라우저가 표시하는 최상위 출처(origin)는 동일한 데이터가 아닐 수 있다. 인증 엔진은 브라우저가 수행해야 하는
origin 검증을 대신했다고 주장해서는 안 된다.

### 12.4 Settings

설정 화면에는 다음 기능을 포함한다.

- 자동 실행 여부
- 시작 시 가상 USB 자동 연결 여부
- 보안 모드 선택
- TPM 상태 표시
- PIN 변경
- 인증기 초기화
- 데이터 보관 경로 확인
- 로그 수준 설정
- 장치 오류 진단

자동 연결 기능을 활성화하더라도 사용자 인증 승인 정책을 우회하지 못하도록 한다.

## 13. 실행 및 종료 수명주기

### 13.1 최초 설치

1. 애플리케이션 설치
2. 가상 USB 드라이버 설치
3. 드라이버 서명 및 무결성 확인
4. 드라이버 정상 작동 여부 확인
5. TPM 상태 확인
6. 인증기 초기화
7. PIN 설정
8. 자격 증명 저장소 초기화
9. 테스트 장치 연결
10. 설치 결과 표시

드라이버 설치 과정에는 관리자 권한이 필요할 수 있다.

### 13.2 프로그램 실행

프로그램이 시작되면 다음 순서로 처리한다.

```text
Launch
  ↓
Environment Check
  ↓
Driver Check
  ↓
Secure Storage Initialization
  ↓
Authenticator Initialization
  ↓
Ready
  ↓
User Connect Request
  ↓
Virtual USB Attachment
  ↓
Device Enumeration
  ↓
Connected
```

### 13.3 프로그램 종료

정상 종료 과정은 다음과 같다.

```text
Exit Request
  ↓
Stop New Requests
  ↓
Cancel Pending Authentication
  ↓
Clear Sensitive Session State
  ↓
Detach Virtual USB Device
  ↓
Stop Local USB/IP Endpoint
  ↓
Close Secure Storage
  ↓
Exit
```

### 13.4 비정상 종료 복구

서비스 또는 관리 프로세스는 다음을 검사해야 한다.

- 앱 종료 후 가상 USB 장치 잔존 여부
- 연결 해제 실패 여부
- 로컬 통신 서비스의 비정상 잔존 여부
- 잠금 파일 및 세션 상태 이상
- 인증 요청이 종료되지 않은 상태
- 메타데이터 갱신 중단 여부

잔여 가상 장치가 발견되면 인증 요청을 차단하고 안전하게 정리해야 한다.

## 14. 내부 서비스 및 IPC

### 14.1 프로세스 구조

권장 프로세스 구조는 다음과 같다.

```text
VirtualFido.Desktop
       |
       | Named Pipe / Authenticated IPC
       v
VirtualFido.Service
       |
       +-- Device Lifecycle
       +-- Authenticator Lifecycle
       +-- Authentication Request Router
       +-- Credential Store
       +-- TPM Provider
       |
       v
Virtual USB Transport
       |
       v
VHCI Driver
```

### 14.2 IPC 보안

UI에서 인증 서비스로 전달하는 요청은 신뢰할 수 없는 입력으로 취급한다.

다음 정책을 적용한다.

- 요청자 식별
- 사용자 세션 검증
- IPC ACL 설정
- 명령별 권한 확인
- 메시지 길이 제한
- 재사용 공격 방지
- 입력 데이터 검증
- 민감 데이터 최소 전송

로컬 통신에 네트워크 프로토콜을 사용하는 경우에도 외부 프로그램이나 네트워크에서 임의로 인증 요청을 생성하지 못하도록 해야 한다.

## 15. 데이터 저장소 설계

### 15.1 Credential Storage

논리적 데이터 구조는 다음과 같다.

```text
credentials
 ├─ credential_id
 ├─ rp_id
 ├─ user_handle
 ├─ user_name
 ├─ display_name
 ├─ public_key
 ├─ key_reference
 ├─ algorithm
 ├─ sign_count
 ├─ discoverable
 ├─ created_at
 ├─ last_used_at
 └─ state
```

### 15.2 Authenticator State

```text
authenticator_state
 ├─ authenticator_id
 ├─ aaguid
 ├─ ctap_version
 ├─ pin_configured
 ├─ pin_retry_state
 ├─ uv_configuration
 ├─ security_mode
 ├─ initialized_at
 └─ state_version
```

### 15.3 Activity Log

```text
authentication_events
 ├─ event_id
 ├─ event_type
 ├─ rp_id
 ├─ credential_reference
 ├─ timestamp
 ├─ result
 ├─ error_code
 └─ duration_ms
```

로그는 기본적으로 민감한 인증 데이터가 아닌 진단 및 감사 목적의 메타데이터만 저장한다.

### 15.4 저장 일관성

- 데이터베이스 트랜잭션 사용
- 원자적 업데이트
- 중복 Credential ID 방지
- 삭제 실패 시 재처리
- TPM 키와 메타데이터의 참조 무결성 확인
- 저장소 스키마 버전 관리
- 애플리케이션 업데이트 시 마이그레이션 지원

## 16. 보안 위협 모델

### 16.1 보호 대상

- FIDO2 개인 키
- PIN 검증 상태
- Credential ID
- 사용자 계정 식별 정보
- 인증기 내부 비밀
- 로컬 IPC
- 인증 승인 상태
- 암호화 저장소
- USB 장치 제어 인터페이스

### 16.2 주요 위협

| 위협 | 대응 방향 |
| --- | --- |
| 개인 키 파일 탈취 | TPM 비추출형 키 |
| 저장소 복사 | 암호화 및 접근 제어 |
| 악성 프로세스의 IPC 접근 | 인증된 IPC 및 ACL |
| 사용자 승인 우회 | 요청별 승인 |
| PIN 무차별 대입 | 시도 제한 및 잠금 |
| 가상 USB 메시지 변조 | 엄격한 파싱 및 검증 |
| 드라이버 취약점 | 최소 기능 및 보안 테스트 |
| 사용자 세션 탈취 | 세션 잠금과 승인 정책 |
| 인증기 데이터 손상 | 무결성 검증 및 트랜잭션 |
| 프로그램 강제 종료 | 안전한 분리 및 상태 복구 |
| 공급망 공격 | 서명된 배포물 및 의존성 검증 |
| 로그를 통한 비밀 유출 | 민감 데이터 로깅 금지 |

### 16.3 명시적 보안 한계

소프트웨어 인증기는 실제 보안 칩이 탑재된 외부 하드웨어 키와 완전히 동일한 신뢰 경계를 제공하지 않는다.

운영체제나 관리자 권한이 침해된 환경에서는 가상 USB 장치, 승인 UI, 로컬 인증 프로세스가 공격당할 수 있다.

TPM은 개인 키 추출 위험을 줄여주지만, 사용자가 승인하지 않은 서명 요청을 차단하기 위한 모든 정책을 자동으로 구현하지는 않는다.

### 16.4 인증기 신뢰성 및 Attestation

프로젝트는 개발용 또는 소프트웨어 인증기라는 특성을 정직하게 나타내야 한다.

다른 제조사의 FIDO 인증서, 인증기 Attestation 키, AAGUID 또는 장치 ID를 무단으로 복제해서는 안 된다.

Attestation이 필수인 서비스에서는 인증이 제한될 수 있다.

## 17. 브라우저 및 웹사이트 호환성

### 17.1 대상

초기 테스트 대상은 다음과 같다.

- Google Chrome
- Microsoft Edge
- Windows WebAuthn 클라이언트
- 일반 WebAuthn 테스트 페이지
- 지원되는 계정 제공자의 보안 키 등록 페이지

### 17.2 호환성 조건

성공적인 등록을 위해 다음이 필요하다.

1. Windows에서 가상 USB 장치가 열거되어야 한다.
2. HID Descriptor가 FIDO 장치 규격과 호환되어야 한다.
3. 브라우저 또는 Windows 인증 클라이언트가 장치를 발견해야 한다.
4. CTAPHID 명령 교환에 성공해야 한다.
5. CTAP2 GetInfo 응답이 유효해야 한다.
6. 사이트의 알고리즘 및 인증 정책과 호환되어야 한다.
7. 사용자 승인과 필요한 사용자 확인이 완료되어야 한다.
8. MakeCredential 또는 GetAssertion이 성공해야 한다.
9. 웹사이트가 최종 결과를 수락해야 한다.

### 17.3 호환성 제한

다음 상황에서는 정상적으로 USB 장치로 인식되더라도 인증이 실패할 수 있다.

- 하드웨어 기반 인증기를 명시적으로 요구하는 사이트
- 특정 Attestation을 요구하는 사이트
- 특정 인증기 인증 수준을 요구하는 정책
- 지원하지 않는 CTAP 확장 기능을 요구하는 서비스
- 사용자 확인 기능이 부족한 경우
- CTAP 버전 또는 옵션 차이
- 운영체제 또는 브라우저의 인증기 필터링

이러한 상황에서 브라우저나 웹사이트의 정책을 우회하는 것이 아니라 지원 범위를 정확하게 표시한다.

## 18. 오류 처리

### 18.1 오류 범주

#### Device Errors

- DRIVER_NOT_INSTALLED
- DEVICE_ATTACH_FAILED
- DEVICE_ENUMERATION_FAILED
- DEVICE_DETACH_FAILED
- USB_TRANSPORT_UNAVAILABLE

#### Authenticator Errors

- CTAP_INVALID_COMMAND
- CTAP_INVALID_CBOR
- CTAP_INVALID_PARAMETER
- CREDENTIAL_NOT_FOUND
- USER_ACTION_TIMEOUT
- USER_DENIED

#### Security Errors

- TPM_UNAVAILABLE
- KEY_OPERATION_FAILED
- STORAGE_LOCKED
- PIN_INVALID
- PIN_BLOCKED
- USER_VERIFICATION_FAILED

#### Application Errors

- SERVICE_UNAVAILABLE
- IPC_AUTHENTICATION_FAILED
- DATABASE_CORRUPTED
- INITIALIZATION_FAILED
- RECOVERY_REQUIRED

내부 오류 코드는 진단 목적으로 사용하며, 브라우저에는 해당 상황에 맞는 표준 CTAP 오류 응답을 반환한다.

## 19. 권장 저장소 구조

```text
virtual-fido/
│
├── src/
│   │
│   ├── VirtualFido.Desktop/
│   │   ├── Views/
│   │   ├── ViewModels/
│   │   ├── Components/
│   │   └── Services/
│   │
│   ├── VirtualFido.Service/
│   │   ├── Lifecycle/
│   │   ├── IPC/
│   │   ├── Sessions/
│   │   └── Recovery/
│   │
│   ├── VirtualFido.Transport/
│   │   ├── UsbIp/
│   │   ├── Hid/
│   │   ├── Descriptors/
│   │   ├── Channels/
│   │   └── Devices/
│   │
│   ├── VirtualFido.Ctap/
│   │   ├── Transport/
│   │   ├── Commands/
│   │   ├── Cbor/
│   │   ├── Pin/
│   │   └── Errors/
│   │
│   ├── VirtualFido.Authenticator/
│   │   ├── Credentials/
│   │   ├── Assertions/
│   │   ├── Attestation/
│   │   ├── Verification/
│   │   └── Policies/
│   │
│   ├── VirtualFido.Security/
│   │   ├── Cryptography/
│   │   ├── Tpm/
│   │   ├── KeyStorage/
│   │   ├── Encryption/
│   │   └── Protection/
│   │
│   ├── VirtualFido.Storage/
│   │   ├── Database/
│   │   ├── Models/
│   │   ├── Migrations/
│   │   └── Repositories/
│   │
│   └── VirtualFido.Contracts/
│       ├── Interfaces/
│       ├── Messages/
│       ├── Events/
│       └── Constants/
│
├── drivers/
│   ├── usbip/
│   └── ude/
│
├── tests/
│   ├── Unit/
│   ├── Integration/
│   ├── Security/
│   ├── Protocol/
│   └── Compatibility/
│
├── tools/
│   ├── Diagnostics/
│   └── TestHarness/
│
├── docs/
│   ├── Architecture.md
│   ├── Security.md
│   ├── Protocol.md
│   ├── Compatibility.md
│   └── Development.md
│
└── README.md
```

`drivers/ude`는 UdeCx 기반 자체 드라이버를 실제로 개발하기 전까지 설계용 위치로만 유지할 수 있다.

## 20. 구현 단계

### Phase 1 — 가상 USB 기반 구현

목표는 물리 장치 없이 Windows가 가상 USB 장치를 인식하는 것이다.

작업:

- USB/IP 및 VHCI 구성 검증
- 가상 USB 컨트롤러 접근
- HID Descriptor 생성
- 가상 장치 연결
- 장치 관리자 열거 확인
- 가상 장치 분리
- 비정상 종료 후 정리

**완료 기준:** 물리 USB 없이 가상 HID 장치가 정상적으로 연결·분리된다.

### Phase 2 — CTAPHID 구현

작업:

- HID 리포트 전송
- INIT
- PING
- CBOR 전송
- 채널 관리
- 메시지 분할과 재조립
- CANCEL
- KEEPALIVE
- ERROR

**완료 기준:** 테스트 클라이언트와 정상적인 CTAPHID 명령을 교환한다.

### Phase 3 — CTAP2 인증기 구현

작업:

- GetInfo
- MakeCredential
- GetAssertion
- ClientPIN
- 자격 증명 저장
- CBOR 처리
- 인증 데이터 생성
- 서명 생성
- PIN 오류 및 취소 처리

**완료 기준:** 테스트 환경에서 WebAuthn 등록과 인증에 성공한다.

### Phase 4 — 보안 기능 통합

작업:

- TPM 키 생성
- TPM 서명 연동
- SQLite 암호화 저장
- 사용자 승인 UI
- PIN 및 잠금 정책
- IPC 접근 제한
- 로그 보안
- 초기화 및 복구

**완료 기준:** 개인 키 추출 없이 서명하고, 승인되지 않은 요청을 거부한다.

### Phase 5 — 데스크톱 애플리케이션 완성

작업:

- 연결 및 분리 버튼
- 장치 상태 표시
- 인증 승인 팝업
- 패스키 목록
- 설정 화면
- 오류 진단
- 설치 프로그램
- 서비스 수명주기

**완료 기준:** 사용자가 명령줄 없이 시스템을 조작할 수 있다.

### Phase 6 — 브라우저 호환성 테스트

작업:

- Chrome 인증
- Edge 인증
- Windows 장치 인식 테스트
- 보안 키 등록
- 패스키 로그인
- PIN 입력
- 사용자 승인
- 등록된 키 재사용
- 사이트별 호환성 비교

**완료 기준:** 최소 하나의 표준 WebAuthn 테스트 환경에서 가상 USB 경로를 통한 등록과 재인증에 성공한다.

### Phase 7 — 안정성 및 보안 검증

작업:

- CTAP 파서 퍼징
- 비정상 메시지 검증
- 서비스 강제 종료
- 드라이버 오류 복구
- 저장소 손상 복구
- TPM 오류 처리
- PIN 반복 실패
- 사용자 승인 타임아웃
- IPC 권한 검사
- 장치 반복 연결·분리
- 장시간 실행 안정성 테스트

**완료 기준:** 정의된 오류 및 보안 검증을 통과하고 알려진 중대한 결함이 해결된다.

## 21. 테스트 및 인수 기준

| 테스트 ID | 검증 내용 | 기대 결과 |
| --- | --- | --- |
| T-001 | 실제 USB 미연결 상태에서 실행 | 정상 실행 |
| T-002 | 가상 USB 연결 | Windows 장치 열거 성공 |
| T-003 | FIDO HID 탐색 | CTAPHID 장치 발견 |
| T-004 | CTAPHID INIT | 정상 응답 |
| T-005 | CTAPHID PING | 데이터 일치 |
| T-006 | CTAP GetInfo | 유효한 응답 |
| T-007 | 신규 Credential 생성 | 정상 생성 |
| T-008 | Credential 기반 인증 | 서명 검증 성공 |
| T-009 | 잘못된 PIN | 오류 반환 |
| T-010 | 인증 요청 거부 | 인증 실패 |
| T-011 | 승인 타임아웃 | 요청 취소 |
| T-012 | TPM 비추출형 키 사용 | 키 내보내기 실패 |
| T-013 | 프로그램 정상 종료 | 가상 장치 분리 |
| T-014 | 프로그램 강제 종료 | 복구 정책 적용 |
| T-015 | 패스키 삭제 | 재인증에 사용 불가 |
| T-016 | 인증기 초기화 | 기존 자격 증명 폐기 |
| T-017 | Chrome 테스트 | 등록 및 인증 |
| T-018 | Edge 테스트 | 등록 및 인증 |
| T-019 | 장치 반복 연결 | 장치 상태 정상 |
| T-020 | IPC 무단 호출 | 접근 거부 |
| T-021 | 저장소 변조 | 무결성 오류 |
| T-022 | 로그인 세션 잠금 | 인증 차단 또는 정책에 따른 취소 |

모든 테스트는 결과를 로그 또는 자동 테스트 보고서로 기록해야 한다.

## 22. 품질 및 비기능 요구사항

### 22.1 안정성

- 일반적인 인증 요청으로 프로그램이 충돌하지 않아야 한다.
- 비정상 입력으로 커널 드라이버가 불안정해지지 않아야 한다.
- 인증 실패 후 정상 상태로 복귀해야 한다.
- 단일 오류가 전체 자격 증명 저장소를 손상시키지 않아야 한다.

### 22.2 유지보수

- USB 전송 구현과 CTAP 명령 엔진을 분리한다.
- 암호화 알고리즘 변경이 가능하도록 추상화한다.
- 스토리지 스키마 마이그레이션을 지원한다.
- 장치 에뮬레이션 드라이버 교체를 고려한다.
- 프로토콜 및 보안 테스트를 자동화한다.

### 22.3 사용자 경험

- 연결 상태가 명확해야 한다.
- 사용자가 승인할 사이트를 식별할 수 있어야 한다.
- 실패 원인에 대한 이해 가능한 메시지를 제공한다.
- 개인 키와 자격 증명을 혼동하지 않도록 UI를 구성한다.
- 잘못된 초기화나 삭제를 방지한다.

### 22.4 배포

- 설치 패키지 무결성 검증
- 코드 서명
- 드라이버 서명 및 설치 정책 확인
- 업데이트 무결성 검증
- 설치 제거 시 가상 장치 정리
- 사용자 데이터 보존 또는 삭제 선택

## 23. 구현 시 별도로 검증할 기술적 쟁점

### 23.1 USB/IP 드라이버 호환성

사용할 VHCI 드라이버가 목표 Windows 11 환경에서 정상 동작하는지 검증해야 한다.

특히 드라이버 서명, 최신 Windows 보안 기능과의 호환성, 배포 라이선스 및 유지보수 상태를 확인해야 한다.

### 23.2 TPM 키 생성 및 서명

선택한 TPM과 Windows CNG 공급자가 CTAP2에 필요한 알고리즘 및 키 관리 정책을 지원하는지 확인해야 한다.

사용자 확인 방식과 TPM 키 사용 권한 정책도 함께 설계해야 한다.

### 23.3 실제 USB 보안 키와의 차이

물리 USB가 없더라도 USB 통신 경로를 소프트웨어로 구현할 수 있지만, 그것이 인증된 물리 보안 키와 동일한 보안 특성을 뜻하지는 않는다.

장치 검색, 프로토콜 호환성, 사이트의 신뢰 정책을 별개로 테스트한다.

### 23.4 Credential 및 Attestation 정책

- ES256 지원
- Discoverable Credential 지원
- PIN/UV 정책
- AAGUID 관리
- Attestation 응답
- 서명 카운터 정책
- 확장 기능 지원

이러한 요소는 표준과 실제 테스트 결과를 근거로 확정해야 한다.

## 24. 참고 구현 및 공식 자료

### 24.1 VirtualFido

Repository:

<https://github.com/keinPlan/virtual-fido>

검토할 구성:

- USB/IP 서버
- VHCI 장치 연결
- CTAPHID 전송
- CTAP2 명령 구현
- GUI 인증 승인
- Credential Storage

기존 프로젝트 코드를 그대로 신뢰하지 않고 라이선스, 보안, 유지보수 상태를 검토한다.

### 24.2 FIDO Alliance CTAP

<https://fidoalliance.org/specifications/>

표준 구현의 기준으로 사용한다.

### 24.3 Microsoft USB Device Emulation

<https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-emulated-device--ude--architecture>

장기적으로 자체 가상 USB 드라이버를 구현할 때 참고한다.

### 24.4 Microsoft UDE Client Driver

<https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver>

Windows 가상 USB 호스트 컨트롤러 및 장치 구현을 위한 참고 자료다.

## 25. 최종 설계 확정 사항

| 항목 | 최종 결정 |
| --- | --- |
| 프로젝트 형태 | Windows 데스크톱 소프트웨어 |
| 물리 USB 필요 여부 | 불필요 |
| 일반 USB 개조 | 하지 않음 |
| 가상 USB 생성 | v1 필수 |
| 장치 유형 | Virtual USB HID FIDO2 |
| USB 에뮬레이션 | USB/IP + VHCI 우선 검토 |
| 대체 구현 | Windows UdeCx |
| 브라우저 인터페이스 | WebAuthn |
| 인증 프로토콜 | CTAP2 / CTAPHID |
| 패스키 생성 | 지원 |
| 패스키 인증 | 지원 |
| 사용자 존재 확인 | 앱 내 명시적 승인 |
| 사용자 검증 | PIN / Windows Hello 연동 검토 |
| 개인 키 저장 | TPM 비추출형 우선 |
| 암호화 메타데이터 | SQLite + Windows 암호화 |
| 소프트웨어 키 대체 모드 | 보안 검토 후 결정 |
| 프로그램 실행 | 가상 USB 연결 기능 제공 |
| 프로그램 종료 | 가상 USB 연결 해제 |
| 웹사이트별 호환성 | 실제 테스트로 검증 |
| 복구 코드 | 계정별 별도 안전 보관 안내 |
| 제조사 하드웨어 인증 사칭 | 금지 |

## 26. v1 최종 완료 정의

프로젝트 v1.0은 다음 조건을 모두 만족하면 완료된 것으로 간주한다.

1. 물리적인 USB 장치 없이 설치하고 실행할 수 있다.
2. 프로그램이 Windows 내부에 가상 USB HID 장치를 생성한다.
3. Windows가 가상 장치를 USB FIDO 인터페이스로 열거한다.
4. CTAPHID 및 필수 CTAP2 명령이 정상 동작한다.
5. 테스트 웹사이트에서 신규 패스키를 생성하고 등록할 수 있다.
6. 등록한 패스키로 인증에 성공할 수 있다.
7. 인증 과정에서 사용자 승인을 요구한다.
8. 가능한 환경에서 TPM 비추출형 키를 사용한다.
9. 저장된 자격 증명을 조회하고 삭제할 수 있다.
10. PIN 설정 및 사용자 확인 정책이 동작한다.
11. 프로그램 종료 시 가상 USB 장치가 분리된다.
12. 비정상 종료 시 잔여 장치 상태를 복구할 수 있다.
13. 인증용 개인 키를 로그나 평문 파일로 노출하지 않는다.
14. 프로토콜 오류 및 보안 테스트를 통과한다.
15. 지원되지 않는 사이트나 인증 정책에 대해 정확한 오류 정보를 제공한다.

---

## 27. 프로젝트 최종 정의

**Virtual FIDO2 Security Key는 물리 USB 없이 Windows에 가상 USB HID 기반 FIDO2 인증 장치를
생성하고, CTAPHID·CTAP2·WebAuthn을 통해 웹사이트 패스키 등록과 인증을 수행하는 소프트웨어 보안 키 시스템이다.**

가상 USB 계층은 운영체제와 브라우저에 표준 USB FIDO 인증기 통신 인터페이스를 제공하며, 인증 엔진은 자격 증명 관리, 사용자 승인,
PIN 처리, 서명 생성 및 오류 처리를 담당한다.

개인 키는 가능한 경우 TPM 2.0의 비추출형 저장 방식을 사용하고, 사용자 계정 정보와 인증기 메타데이터는 보호된 로컬 저장소에서 관리한다.

프로그램은 가상 USB 장치의 연결과 분리를 제어하고, 사용자가 별도의 하드웨어 보안 키를 소유하지 않아도 표준 WebAuthn 인증을 사용할
수 있는 환경을 제공하는 것을 목표로 한다.

이 프로젝트의 핵심은 **USB 장치의 물리적 존재를 구현하는 것이 아니라, USB FIDO2 인증기의 표준 인터페이스와 인증 동작을
소프트웨어로 구현하는 것**이다.
