# Virtual FIDO2 Security Key

> 물리 USB 없이 동작하는 소프트웨어 기반 가상 USB 보안 키 시스템 설계 명세서

**문서 버전:** 1.1
**작성 기준일:** 2026-10-28
**프로젝트 유형:** Cross-platform Desktop Application / Virtual HID / FIDO2 Authenticator
**목표 플랫폼:** Windows, macOS, Linux (지원 버전은 플랫폼 검증 단계에서 확정)
**공통 언어:** Rust
**데스크톱 UI:** Tauri 2 (계획)
**개발 상태:** 멀티플랫폼 아키텍처 결정 및 기술 검증 단계

## 0. 멀티플랫폼 아키텍처 개정 사항

이 절은 Windows 전용 초안에서 멀티플랫폼 설계로 전환하기 위한 최신 기준선이다. 아래 내용과 본문 중 플랫폼별 구현 세부가 충돌하면 이 절과 `resources/STEP.md`를 우선한다. 기존 Windows 전용 절은 공통 CTAP·보안 요구사항의 참고 자료로 남기며, 플랫폼별 구현 근거 없이 다른 운영체제에 그대로 적용하지 않는다.

### 0.1 제품 범위

v1은 물리 USB 없이 Windows, macOS, Linux 모두에서 운영체제의 인증기 탐색 경로에 가상 FIDO HID 인증기를 제공해야 한다. 각 OS 공급자가 보안 업데이트를 제공하는 데스크톱 OS 버전을 대상으로 하며, x64와 ARM64를 지원한다. Linux 배포판은 Ubuntu LTS를 우선 대상으로 삼는다. OS 버전·CPU 아키텍처별 지원은 해당 OS 가상 HID 경로와 브라우저/WebAuthn 검증을 통과한 조합에 한정하며 모든 웹사이트 호환성을 보장하지 않는다.

지원표에는 OS 공급자 보안 업데이트 여부, x64/ARM64 빌드, 가상 장치 열거, 권한·설치, Chrome/Edge WebAuthn 결과를 버전별로 기록한다. OS 버전이 보안 지원에서 제외되거나 CPU 아키텍처에서 native adapter를 제공하지 못하면 해당 조합은 지원하지 않는다. Linux는 보안 업데이트 중인 Ubuntu LTS 릴리스부터 검증하고 다른 배포판은 별도 검증 전까지 보장하지 않는다.

### 0.2 공통 기술과 플랫폼별 기술

| 영역 | 기준 기술 | 책임 |
| --- | --- | --- |
| 데스크톱 UI | Tauri 2, React, TypeScript, Rust backend | 상태, 설정, 승인, 플랫폼 상태 표시 |
| 공통 인증기 코어 | Rust workspace | CTAPHID, CBOR, CTAP2, 자격 증명 정책 및 공통 오류 모델 |
| 플랫폼 경계 | Rust trait/API 및 제한된 IPC | 공통 코어와 OS 기능을 분리하고 실패를 명시적으로 전달 |
| Linux 가상 HID | `/dev/uhid` 사용자 공간 어댑터 후보 | x64/ARM64에서 UHID 수명주기, report 전달, 권한·Ubuntu LTS 배포 검증 |
| Windows 가상 HID | UdeCx/KMDF 기반 네이티브 드라이버 후보 | x64/ARM64 장치 열거, 드라이버 서명·설치·제거 검증 |
| macOS 가상 HID | CoreHID virtual device API 및 entitlement 후보 | 지원되는 x64/ARM64 조합, entitlement, 서명·배포와 브라우저 인식 검증 |
| 암호 키 보관 | 플랫폼별 `KeyStore` provider | TPM, Secure Enclave 또는 OS 보호 저장소 등 실제 제공 능력을 보고하고 정책 적용 |
| 메타데이터 | SQLite 등 공통 저장소 후보 | 민감한 개인 키 원문은 저장하지 않고 OS 보호 저장소의 key reference만 저장 |

Tauri는 React/TypeScript UI 구현을 공유하지만 가상 HID 장치·드라이버·보안 저장소를 자동으로 멀티플랫폼화하지 않는다. OS별 드라이버, entitlement, 권한, 패키징과 호환성 검증은 각 플랫폼과 CPU 아키텍처에서 따로 수행한다.

### 0.3 모듈 책임 경계

- `ghost-fido-core`: 플랫폼 API에 의존하지 않는 CTAPHID·CTAP2·CBOR 및 인증기 도메인 로직을 소유한다.
- `ghost-platform`: 장치 lifecycle, HID report I/O, 키 보관, 사용자 확인 기능을 trait 기반 provider로 노출한다.
- `apps/ghost-fido`: 개발용 실행 진입점이다. 제품 UI는 `apps/desktop`에 Tauri 앱으로 추가한다.
- `platforms/linux`, `platforms/windows`, `platforms/macos`: 각 OS의 네이티브 어댑터와 드라이버 프로젝트를 둔다. 커널·드라이버 코드는 플랫폼 요구에 따라 Rust 이외의 언어를 사용할 수 있다.
- CTAP 코어는 실제 USB 버스나 특정 OS의 장치 API를 직접 호출하지 않는다.

모든 provider는 가용 여부와 보안 보장을 명시해야 한다. 구현되지 않았거나 entitlement·권한이 없는 provider는 장치를 사용할 수 있다고 표시하지 않고 안전하게 실패한다.

### 0.4 플랫폼별 기술 검증 게이트

| 플랫폼 | 조사할 경로 | 출시 전 필수 증거 |
| --- | --- | --- |
| Linux | 커널 UHID (`/dev/uhid`) | 보안 업데이트 중인 Ubuntu LTS의 x64/ARM64에서 권한·udev, HID 열거, 브라우저 FIDO 발견과 CTAPHID 왕복 |
| Windows | UdeCx/KMDF 가상 USB/HID 드라이버 | 보안 업데이트 중인 Windows x64/ARM64에서 드라이버 서명·설치·제거, 장치 열거와 브라우저 report 왕복 |
| macOS | CoreHID virtual device API와 `com.apple.developer.hid.virtual.device` entitlement 검토 | 보안 업데이트 중인 macOS 및 x64/ARM64 지원 조합에서 entitlement, 코드 서명, HID 열거와 브라우저 탐색 |

macOS entitlement와 가상 HID 공개 API의 실제 배포 가능성을 검증하기 전에는 macOS 제품 배포를 약속하지 않는다. Windows와 Linux 역시 장치가 OS에 열거된 것만으로 WebAuthn 경로가 검증되었다고 간주하지 않는다.

#### 조사 결과와 지원 차단 조건

| 필수 조합 | 공식 문서로 확인된 기반 | 현재 판정 | 제품 지원 전 증거 |
| --- | --- | --- | --- |
| Ubuntu LTS x64 | UHID userspace API 및 `/dev/uhid` event protocol 존재 | candidate; 배포 권한과 WebAuthn 미검증 | 대상 Ubuntu LTS의 장치 생성·report 왕복, 일반 사용자 권한, Chrome/Edge 등록·assertion |
| Ubuntu LTS ARM64 | UHID userspace API는 CPU 중립적인 Linux HID 경로 | candidate; ARM64 실제 빌드·장치·WebAuthn 미검증 | ARM64 빌드 및 위와 같은 실장치 검증 |
| Windows x64 | UDE/UdeCx와 KMDF client driver 개발 경로 문서화 | candidate; product driver 및 브라우저 미검증 | 서명·설치 가능한 x64 driver, HID/FIDO 발견, Chrome/Edge 등록·assertion |
| Windows ARM64 | WDK ARM64 driver 개발/배포 지원 문서화 | candidate; native UDE driver 및 브라우저 미검증 | native ARM64 driver build/sign/install 및 ARM64 기기에서 end-to-end WebAuthn |
| macOS x64 | CoreHID virtual HID API와 entitlement가 문서화됨 | blocked pending entitlement/distribution and runtime proof | Intel Mac에서 entitlement가 포함된 배포 서명 앱, HID report와 browser WebAuthn 왕복 |
| macOS ARM64 | CoreHID virtual HID API와 entitlement가 문서화됨 | blocked pending entitlement/distribution and runtime proof | Apple silicon에서 entitlement가 포함된 배포 서명 앱, HID report와 browser WebAuthn 왕복 |

- Linux UHID는 userspace HID transport driver가 `/dev/uhid`를 열고 create, input, output, get/set report, destroy 이벤트를 교환하는 인터페이스다. `/dev/uhid` device node는 udev 등으로 제공되므로 Ubuntu LTS의 x64/ARM64에서 일반 사용자 권한 경로와 package 설치 규칙을 별도로 검증한다.
- Windows UDE 가상 USB host controller와 기기는 WDK/UdeCx를 사용하는 KMDF driver로 구현해야 한다. Windows on Arm에서는 kernel-mode driver가 native ARM64여야 하며, x64 앱 에뮬레이션은 driver를 대체하지 않는다. 서명, 설치 elevation, 제거를 실제 x64/ARM64 기기에서 검증한다.
- macOS CoreHID `HIDVirtualDevice`는 가상 HID 생성 API를 제공하지만 `com.apple.developer.hid.virtual.device` entitlement가 필요하다. entitlement 승인, 배포 서명, 지원 macOS 버전, Intel/Apple silicon의 report 동작 및 Chrome/Edge WebAuthn 왕복이 입증될 때까지 macOS를 배포 가능하다고 간주하지 않는다.
- 세 OS 모두 descriptor가 HID로 열거되는 것과 브라우저가 이를 FIDO authenticator로 사용하는 것은 별도 게이트다. 서명·패키징한 실제 빌드에서 등록과 인증 CTAPHID 왕복을 확인한 OS/version/architecture만 지원표에 올린다.
- OS 공급자의 보안 지원 버전은 바뀌므로 하드코딩하지 않고 각 릴리스 시점에 공식 지원 정책을 다시 확인한다.

### 0.5 문서 간 우선순위 및 보안 경계

`STEP.md`는 구현 순서와 단계별 통과 기준을 정의한다. 이 절은 멀티플랫폼 제품 범위와 아키텍처의 현재 기준이다. 아래 본문의 Windows 전용 기술명과 UI 예시는 해당 OS의 구현 예로만 해석한다.

공통 보안 원칙은 유지한다. 사용자 명시적 승인 없는 서명을 금지하고, 타사 제조사 VID/PID, AAGUID, 인증서 또는 attestation을 사칭하지 않으며, 물리 보안 키와 동등한 보안 보증을 하지 않는다. 플랫폼별 하드웨어 키 보호 능력은 지원 OS별로 따로 설명한다.

키 생성은 플랫폼의 보호 저장소를 기본 사용한다. 하드웨어 보호 키를 사용할 수 없는 경우 소프트웨어 키로 자동 전환하지 않는다. 사용자가 보안 차이를 설명받고 명시적으로 동의한 경우에만 소프트웨어 키를 생성하며, UI에는 해당 credential의 보호 수준을 계속 표시한다.

### 0.6 공식 플랫폼 참고 자료

- [Rust 플랫폼 지원 등급](https://doc.rust-lang.org/rustc/platform-support.html)
- [Tauri 2 플랫폼별 사전 요구사항](https://v2.tauri.app/start/prerequisites/)
- [Linux UHID 문서](https://docs.kernel.org/hid/uhid.html)
- [FIDO CTAP HID descriptor 및 discovery](https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.pdf)
- [Rust uhid-virt wrapper](https://docs.rs/uhid-virt/latest/uhid_virt/)
- [Windows UDE Client Driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver)
- [Windows UDE driver boundary scaffold](../platforms/windows/ude/README.md)
- [Apple CoreHID HIDVirtualDevice](https://developer.apple.com/documentation/corehid/hidvirtualdevice)
- [Apple 가상 HID entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device)
- [macOS CoreHID driver boundary scaffold](../platforms/macos/corehid/README.md)
- [Windows UDE 드라이버 개요](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/developing-windows-drivers-for-emulated-usb-host-controllers-and-devices)
- [Windows ARM 드라이버 요건](https://learn.microsoft.com/en-us/windows/arm/faq)
- [Windows ARM64 WDK 지원](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/building-arm64-drivers)

---

## 1. 프로젝트 개요

### 1.1 프로젝트 정의

Virtual FIDO2 Security Key는 **별도의 물리적 USB 장치 없이, 프로그램 실행만으로 Windows·macOS·Linux에 가상 FIDO HID 인증기를 제공하는 멀티플랫폼 소프트웨어**다.

사용자가 프로그램을 실행하고 가상 보안 키를 활성화하면 운영체제는 USB HID 인증 장치가 연결된 것처럼 인식한다.

Chrome, Edge 등의 브라우저와 각 운영체제의 WebAuthn 경로에서 전달되는 요청은 해당 OS의 가상 HID 어댑터를 거쳐 공통 FIDO2 인증 엔진으로 전달된다.

인증 엔진은 사용자의 승인을 받은 후 보호된 개인 키로 암호학적 서명을 생성하고, 표준 FIDO2 응답을 반환한다.

사용자는 이를 활용하여 지원되는 웹사이트에 패스키 또는 FIDO2 보안 키를 등록하고 로그인할 수 있어야 한다.

프로젝트는 하드웨어 보안 키의 기능적 동작을 소프트웨어로 구현하는 것이 목적이며, 물리적 보안 칩을 갖춘 인증기와 동일한 보안 수준을 보장한다고
주장하지 않는다.

### 1.2 핵심 원칙

1. 물리 USB 장치가 필요 없어야 한다.
2. 일반 USB 메모리를 개조하거나 포맷할 필요가 없어야 한다.
3. 프로그램 내부에서 가상 USB 장치를 생성해야 한다.
4. 지원 대상 운영체제가 해당 장치를 FIDO HID 인증기로 열거할 수 있어야 한다.
5. 표준 FIDO2 / CTAP2 인증 요청을 처리해야 한다.
6. WebAuthn 호환 브라우저에서 인증에 사용할 수 있어야 한다.
7. 인증용 개인 키는 외부에 노출하지 않아야 한다.
8. 플랫폼 보호 저장소를 기본 사용하고, 보호 수준을 credential별로 표시해야 한다.
9. 사용자의 명시적 승인 없이 인증을 완료해서는 안 된다.
10. 프로그램 종료 시 가상 HID 장치를 연결 해제해야 한다.
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
| G-001 | 물리 USB 없는 가상 FIDO HID 장치 생성 | 필수 |
| G-002 | 지원 운영체제의 FIDO HID 장치 열거 | 필수 |
| G-003 | FIDO CTAPHID 통신 지원 | 필수 |
| G-004 | CTAP2 인증기 구현 | 필수 |
| G-005 | WebAuthn 등록 및 인증 | 필수 |
| G-006 | 패스키 자격 증명 관리 | 필수 |
| G-007 | 플랫폼별 보호 키 저장소 연동 | 필수 목표 |
| G-008 | 사용자 승인 인터페이스 | 필수 |
| G-009 | OS별 가상 HID 연결 및 분리 | 필수 |
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
- 지원 매트릭스에 포함되지 않은 운영체제 및 버전 지원
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
| OS | Windows, macOS, Linux; 버전과 아키텍처는 단계별 지원 매트릭스로 확정 |
| 공통 코어 | Rust workspace |
| 데스크톱 UI | Tauri 2, React, TypeScript, Rust backend |
| 플랫폼 HID | Linux UHID, Windows UdeCx/KMDF, macOS CoreHID 후보; 각각 독립 검증 |
| 키 보관 | 플랫폼별 `KeyStore` provider; 하드웨어 보호 수준을 기능별로 보고 |
| 승인 및 확인 | 공통 승인 정책과 OS별 사용자 확인 provider |
| 메타데이터 저장 | SQLite 후보, 개인 키 원문 저장 금지 |
| 통신 직렬화 | CBOR |
| 진단 및 테스트 | Rust tooling, Tauri tooling, OS별 SDK 및 WebAuthn 테스트 환경 |

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

`options.up`이 생략되면 사용자 존재를 요구한다. `options.up`이 `false`이면
플랫폼이 허용 목록 또는 제외 목록을 미리 확인하는 요청으로 처리하며 사용자 승인
화면을 띄우지 않는다. 이때 서명된 인증 데이터의 UP 비트는 0이어야 한다. UV 비트는
유효한 PIN/UV 인증이 검증된 경우에만 1로 설정한다. 이어지는
`authenticatorGetNextAssertion` 응답도 원래 요청의 UP 및 UV 상태를 유지한다.

이 규칙은 `authenticatorGetAssertion`에 적용한다. `authenticatorMakeCredential`의
`options.up = false`는 계속 지원하지 않는다.

처리 절차:

1. 로그인 요청 수신
2. rpId 및 Credential ID 일치 여부 검사
3. 관련 자격 증명 탐색
4. 사용자 존재 및 확인 정책 검사
5. `up`이 생략되거나 `true`이면 사용자 승인 요청; `false`이면 승인 화면 생략
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

CTAP Credential Management 요청은 command 맵, 매개변수를 받는 subcommand의 매개변수 맵, 중첩된 user entity 및 descriptor 맵에서 구현이 이해하지 못하는 키를 무시한다. HMAC 인증에는 전체 인코딩된 `subCommandParams`를 사용한다. 삭제 및 사용자 정보 변경 요청은 `PublicKeyCredentialDescriptor`의 필수 `type`과 `id`를 검증하고, 선택적 `transports` 문자열 배열을 검증한 뒤 값은 무시한다. 중복 키와 잘못된 필수 또는 지원 필드는 거부하며, 매개변수를 받지 않는 subcommand의 매개변수 맵은 계속 거부한다.

필수 `credentialId` 또는 `user` subcommand 매개변수가 없으면 `MISSING_PARAMETER`를 반환한다. 매개변수가 있지만 CBOR 형태가 잘못되었거나, 중첩된 descriptor/user entity의 필수 필드가 없거나 형식이 잘못된 경우에는 `CBOR_UNEXPECTED_TYPE`을 반환한다. 선택적 `transports`, `name`, `displayName` 필드도 형식이 잘못되면 `CBOR_UNEXPECTED_TYPE`을 반환하고, 의미상 유효하지 않은 값은 기존 매개변수 오류로 처리한다.

단, Windows 앱에서 직접 수행하는 관리 기능과 CTAP 표준을 통해 제공하는 Credential Management 기능을 별도로
구현하고 검증한다.

CTAP `updateUserInformation`은 기존 `user.id`를 변경하지 않으며, 생략되거나 빈 `name`/`displayName` 필드는 해당 저장 필드를 삭제한다.

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
- 자격 증명 삭제와 TPM 키 삭제의 정합성을 유지하며, 프로세스 중단 후에도 보호된 삭제 의도를 복구해 삭제된 키를 가리키는 자격 증명을 남기지 않는다.
- 여러 프로세스가 같은 저장소를 열더라도 자격 증명 및 PIN 변경은 최신 보호 상태를 보존하고, 동일 항목 충돌이나 초기화 진행 중의 변경은 거부한다. 공급자 키 정리 journal은 대상 핸들이 일치할 때만 완료 처리한다.
- 장기 실행 authenticator는 각 CTAP 요청 시작 시 보호된 자격 증명, PIN 및 정리 journal의 유효한 스냅샷을 새로 읽는다. 자격 증명이나 PIN 상태가 달라지면 assertion/credential-management continuation과 ClientPIN agreement/token을 폐기한다. 새로 발견되거나 서로 모순되는 정리 의도는 fail closed 처리하고, 중지 상태의 desktop 자격 증명 조회도 공유 저장소를 새로 읽는다.
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

플랫폼 보호 키를 사용할 수 없는 경우 기본적으로 키 생성을 거부한다. 사용자가 소프트웨어 키의 보안 차이를 설명받고 명시적으로 동의하면 software fallback을 선택할 수 있다.

#### Strict Mode

- TPM을 필수로 요구한다.
- 비추출형 키를 생성하지 못하면 인증기 초기화를 거부한다.
- 높은 보안 요구사항이 있는 기본 권장 모드다.

#### Software Fallback Mode

- 암호화된 소프트웨어 키를 사용한다.
- 별도의 사용자 승인과 명시적 위험 고지가 필요하다.
- 하드웨어 기반 비추출 보장을 제공하지 않는다.
- v1은 위험 고지와 명시적 사용자 동의를 받은 경우에만 허용한다.

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
- CTAPHID 채널 lease가 만료되면 진행 중 요청을 취소하고 해당 채널의 assertion, credential-management, ClientPIN 상태를 모두 폐기한다.
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

`resources/STEP.md`가 현재 구현 순서와 단계별 완료 기준의 기준 문서다. 이 절의 이전 Windows 전용 Phase 계획을 대체한다.

1. 지원 OS·버전·아키텍처와 Tauri/Rust 빌드 조건을 확정한다.
2. Linux UHID, Windows UdeCx/KMDF, macOS CoreHID 후보를 각각 최소 구현으로 검증하고 출시 플랫폼을 선정한다.
3. Rust 공통 core와 Tauri UI, OS adapter 경계를 구현한다.
4. 각 지원 OS의 가상 HID와 lifecycle을 구현한다.
5. 공통 CTAPHID, CBOR, CTAP2와 credential 흐름을 구현한다.
6. OS별 키 저장소, 사용자 확인, UI 승인과 데이터 보호를 통합한다.
7. 각 OS·브라우저 조합에서 WebAuthn 상호운용, 안정성, 보안, 설치·업데이트·제거를 검증한다.
8. 검증된 플랫폼만 지원 대상으로 공개한다.

## 21. 테스트 및 인수 기준

각 테스트는 지원한다고 선언하는 OS·버전·아키텍처 조합에서 반복한다. 결과에는 OS 빌드, 브라우저 버전, backend 및 key provider 상태를 기록한다.

| 테스트 ID | 검증 내용 | 기대 결과 |
| --- | --- | --- |
| T-001 | 실제 USB 미연결 상태에서 실행 | 정상 실행 |
| T-002 | 플랫폼 adapter를 통한 가상 HID 연결 | 대상 OS에서 HID 장치 열거 성공 |
| T-003 | FIDO HID 탐색 | 지원 브라우저가 authenticator 발견 |
| T-004 | CTAPHID INIT | 정상 응답 |
| T-005 | CTAPHID PING | 데이터 일치 |
| T-006 | CTAP GetInfo | 유효한 응답 |
| T-007 | 신규 Credential 생성 | 정상 생성 |
| T-008 | Credential 기반 인증 | RP 서명 검증 성공 |
| T-009 | 잘못된 PIN | 오류 반환 |
| T-010 | 인증 요청 거부 | 인증 실패 |
| T-011 | 승인 타임아웃 | 요청 취소 |
| T-012 | 선택한 보호 키 provider 사용 | provider 정책에 따른 비추출성 검증 |
| T-013 | 프로그램 정상 종료 | 가상 HID 장치 분리 |
| T-014 | 프로그램 강제 종료 | 플랫폼 복구 정책 적용 |
| T-015 | 패스키 삭제 | 재인증에 사용 불가 |
| T-016 | 인증기 초기화 | 기존 자격 증명 폐기 |
| T-017 | Chrome 테스트 | 지원 OS에서 등록 및 인증 |
| T-018 | Edge 테스트 | 지원 OS에서 등록 및 인증 |
| T-019 | 장치 반복 연결 | 장치 상태 정상 |
| T-020 | IPC 무단 호출 | 접근 거부 |
| T-021 | 저장소 변조 | 무결성 오류 |
| T-022 | 로그인 세션 잠금 | 인증 차단 또는 정책에 따른 취소 |
| T-023 | 플랫폼 권한·드라이버·entitlement 누락 | 안전하게 비활성화되고 실행 가능한 안내 제공 |
| T-024 | 설치·업데이트·제거 | 장치 정리 및 사용자 데이터 정책 준수 |

모든 테스트는 자동화 결과 또는 수동 재현 절차로 기록한다. 장치 열거만 성공하고 브라우저가 발견하지 못한 경우 T-003과 WebAuthn 인수 기준은 통과한 것으로 보지 않는다.
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
| 프로젝트 형태 | Rust 공통 코어를 사용하는 멀티플랫폼 데스크톱 소프트웨어 |
| v1 필수 운영체제 | Windows, macOS, Linux |
| OS 버전 정책 | 각 공급자가 보안 업데이트를 제공하는 데스크톱 버전 |
| CPU 아키텍처 | x64와 ARM64; OS별 가상 HID 경로에서 검증된 조합 |
| Linux 배포판 | Ubuntu LTS 우선, 보안 업데이트 중인 릴리스 |
| 물리 USB 필요 여부 | 불필요 |
| 일반 USB 개조 | 하지 않음 |
| 가상 FIDO HID 생성 | 지원을 선언하는 각 OS에서 필수 |
| 장치 유형 | OS별 가상 HID 기반 FIDO2 |
| 공통 UI | Tauri 2 + React + TypeScript |
| OS별 장치 경로 | Linux UHID, Windows UdeCx/KMDF, macOS CoreHID 후보 검증 |
| 브라우저 인터페이스 | WebAuthn |
| 인증 프로토콜 | CTAP2 / CTAPHID |
| 패스키 생성 | 지원 |
| 패스키 인증 | 지원 |
| 사용자 존재 확인 | 앱 내 명시적 승인 |
| 사용자 검증 | PIN과 OS별 사용자 확인 기능을 분리 검증 |
| 개인 키 저장 | OS별 보호 키 저장소, 가용성과 보장 수준 표시 |
| 암호화 메타데이터 | SQLite 후보 + OS별 보호 기능 |
| 키 저장 우선순위 | 플랫폼 보호 저장소 우선; hardware-backed 여부와 exportability를 노출 |
| 소프트웨어 키 대체 모드 | 자동 전환 금지; 위험 고지와 명시적 사용자 동의 후 허용 |
| 프로그램 실행 | 가상 USB 연결 기능 제공 |
| 프로그램 종료 | 가상 USB 연결 해제 |
| 웹사이트별 호환성 | 실제 테스트로 검증 |
| 복구 코드 | 계정별 별도 안전 보관 안내 |
| 제조사 하드웨어 인증 사칭 | 금지 |

## 26. v1 최종 완료 정의

프로젝트 v1.0은 지원한다고 선언하는 각 OS·버전·아키텍처 조합에서 다음 조건을 만족하면 완료된 것으로 간주한다. 멀티플랫폼 지원을 주장하려면 세 OS 모두의 필수 검증을 통과해야 한다.

현재 OS·아키텍처·브라우저별 빌드 및 실제 검증 증거는 [플랫폼 및 브라우저 지원 근거표](../docs/support-matrix.md)에서 추적한다. CI 빌드만으로 지원 여부를 확정하지 않는다.

1. 물리적인 USB 장치 없이 설치하고 실행할 수 있다.
2. 프로그램이 해당 OS의 승인된 가상 HID 경로를 통해 장치를 생성한다.
3. OS와 대상 브라우저가 가상 장치를 FIDO authenticator로 발견한다.
4. CTAPHID 및 필수 CTAP2 명령이 정상 동작한다.
5. 테스트 웹사이트에서 신규 패스키를 생성하고 등록할 수 있다.
6. 등록한 패스키로 인증에 성공할 수 있다.
7. 인증 과정에서 사용자 승인을 요구한다.
8. 플랫폼별 키 저장소의 보호 수준을 정확히 표시하고 해당 provider 정책을 따른다.
9. 저장된 자격 증명을 조회하고 삭제할 수 있다.
10. PIN 설정 및 사용자 확인 정책이 동작한다.
11. 프로그램 종료 시 가상 HID 장치가 분리된다.
12. 비정상 종료 시 잔여 장치 상태를 복구할 수 있다.
13. 인증용 개인 키를 로그나 평문 파일로 노출하지 않는다.
14. 프로토콜 오류 및 보안 테스트를 통과한다.
15. 지원되지 않는 사이트나 인증 정책에 대해 정확한 오류 정보를 제공한다.

---

## 27. 프로젝트 최종 정의

**Virtual FIDO2 Security Key는 Rust 공통 인증기 코어와 Tauri 데스크톱 UI를 사용하고, 각 지원 OS의 가상 HID 경로를 통해 물리 USB 없이 FIDO2 인증 장치를 제공하는 멀티플랫폼 소프트웨어 인증기다.**

각 OS 어댑터는 운영체제의 HID 장치 lifecycle과 report I/O를 담당한다. 공통 인증 엔진은 CTAPHID·CTAP2·CBOR, 자격 증명 관리, 사용자 승인, PIN 처리, 서명 요청 및 오류 처리를 담당한다.

개인 키는 OS별 보호 키 저장 provider를 통해 관리한다. TPM, Secure Enclave 또는 OS 보호 저장소의 가용성은 플랫폼별로 확인하고 실제 보장 수준을 사용자에게 표시한다. 사용자 계정 정보와 인증기 메타데이터는 보호된 로컬 저장소에서 관리한다.

공통 CTAPHID report framing은 `ghost-fido-core`가 소유하며, OS 어댑터는 64-byte report transport만 제공한다. framing 계층은 채널, 명령, 순번, payload 크기를 검증하고 CTAP command/CBOR 처리는 후속 단계로 분리한다. 구현 경계는 [`docs/ctaphid-framing.md`](../docs/ctaphid-framing.md)에 기록한다.

CTAPHID broadcast INIT는 8-byte nonce를 검증한 뒤 고유 channel을 할당하고 nonce를 echo한 17-byte 응답 payload를 반환한다. channel capacity exhaustion과 잘못된 nonce 길이는 별도 오류다. [`docs/ctaphid-init.md`](../docs/ctaphid-init.md)

CTAPHID channel allocator는 broadcast channel(`0xffffffff`)과 channel zero를 예약하고, 동시 요청별 deadline을 추적해 만료 시 channel을 회수한다. 타이머와 오류 report 전송은 호출자에 남겨 OS별 runtime 차이를 격리한다. [`docs/ctaphid-channels.md`](../docs/ctaphid-channels.md)

CTAP2 core는 command byte와 status-prefixed response, bounded CBOR, 명시적으로 설정한 GetInfo 응답 및 typed MakeCredential/GetAssertion 요청을 제공한다. `ghost-platform::AuthenticatorService`는 GetInfo, MakeCredential, GetAssertion, GetNextAssertion을 기존 provider 흐름에 연결한다. `AuthenticatorHidSession`은 CTAPHID report session의 요청을 채널 정보와 함께 서비스에 전달하고 CTAP2 응답을 다시 report로 인코딩한다. Assertion continuation은 CTAPHID channel마다 보관하고 30초 후 만료되며, 다른 명령이 해당 channel에서 처리되거나 채널이 취소·만료되면 지운다.

데스크톱 Tauri runtime은 현재 이 report path를 host virtual HID backend에 연결한다. `start_authenticator`가 host backend를 선택해 `authenticator_runtime::run`을 시작하고, worker는 backend를 attach한 뒤 input report를 CTAPHID session/service로 전달하고 response report를 쓴다. 이는 코드 연결 상태이며 target OS에서 장치 enumeration/report 교환이나 browser WebAuthn 호환성을 검증한 결과가 아니다. 각 target의 증거와 지원 상태는 [`docs/support-matrix.md`](../docs/support-matrix.md)를 따른다. 서비스 경계와 표준 status 값은 [`docs/ctap2-dispatch.md`](../docs/ctap2-dispatch.md), [`docs/ctaphid-service.md`](../docs/ctaphid-service.md)에 기록한다.

CTAP2 입력 CBOR는 definite-length 값만 허용하며 기본 16 depth, 128 collection items, 8192 bytes 제한을 적용한다. 잘린 입력, indefinite form, 지원하지 않는 simple/float 값, 잘못된 UTF-8과 trailing data는 handler 전에 거부한다. [`docs/cbor-validation.md`](../docs/cbor-validation.md)

`GetInfoProfile`은 versions, AAGUID, options, max message size와 PIN/UV protocol을 명시적으로 주입해야만 응답을 직렬화한다. 기본 profile은 제공하지 않아 미완성 authenticator가 기능을 과장하지 않는다. [`docs/ctap2-getinfo.md`](../docs/ctap2-getinfo.md)

ClientPIN은 PIN/UV Auth Protocol 1의 기존 암호 동작을 유지하면서 Protocol 2의 분리된 HKDF 키, random-IV AES-CBC, 32-byte HMAC을 지원한다. agreement, token 및 요청 검증은 선택한 protocol에 묶고, 명시적 비지원 protocol ID는 거부한다. 명시적 COSE `keyAgreement`의 `kid`, `key_ops`, `base IV` label과 EC2 private-key parameter `d` (-4)는 허용하지 않고, 알 수 없는 map key는 CTAP §8에 따라 무시한다.`subCommand` 누락, 잘못된 CBOR type, 미지원 숫자 subcommand는 각각 `MissingParameter`, `CborUnexpectedType`, `InvalidSubcommand`로 구분한다. 지원 subcommand의 필수 파라미터가 없으면 `MissingParameter`, 알려진 파라미터의 CBOR type이 틀리면 `CborUnexpectedType`를 반환하며 malformed request는 PIN retry를 소비하지 않는다. GetInfo는 `[2, 1]` 순서로 프로토콜을 노출하며 CTAP2.1 필수 기능 조건이 모두 성립할 때만 `FIDO_2_1`과 `pinUvAuthToken`을 광고한다. MakeCredential 또는 `up=true` GetAssertion에서 user presence 승인이 끝나면 token의 모든 permission을 `lbw` 외에는 제거하고, silent GetAssertion preflight (`up=false`)에서는 permission을 유지한다. 3회 연속 잘못된 PIN 검증은 `PIN_AUTH_BLOCKED`를 반환하고 현재 authenticator runtime이 종료·재시작될 때까지 PIN subcommand를 잠근다. 이 상태에서 GetPINRetries는 `powerCycleState=true`를 반환하며, 올바른 PIN 검증은 새 PIN 검증이 실패하더라도 연속 실패 횟수를 초기화한다. [`docs/ctap2-clientpin.md`](../docs/ctap2-clientpin.md)
`GetAssertionRequest`는 CBOR 필수 필드, 32-byte `clientDataHash`, optional `public-key` allow-list descriptor와 `up`/`uv` boolean 옵션을 검증한다. RP ID의 SHA-256 hash를 사용해 allow-list 또는 discoverable credential을 RP별로 조회한다. allow-list가 없고 여러 discoverable credential이 일치하면 생성 순서 역순으로 첫 응답과 `numberOfCredentials`를 반환하고, 나머지는 channel별 `GetNextAssertion` sequence로 이어진다. 승인과 key provider 서명은 최초 요청에서 한 번 수행하며, 각 응답의 counter를 저장한 뒤 반환한다. UV 없이 user handle 외 이름 정보는 노출하지 않는다. [`docs/ctap2-getassertion.md`](../docs/ctap2-getassertion.md)

`hmac-secret` 입력 맵은 CTAP2 §8에 따라 알 수 없는 키를 무시하고, 지원하는 필수 필드와 `pinUvAuthProtocol`의 값/길이만 검증한다. `keyAgreement`는 map이어야 하며, 제공된 `pinUvAuthProtocol`은 unsigned integer여야 한다. 지원하지 않는 unsigned protocol ID는 `InvalidParameter`로 처리한다. 선택된 credential에 `CredRandom`이 없으면 hmac-secret 요청의 인증·복호화 검증은 계속 수행한 뒤 extension 출력을 생략하고 assertion을 성공시킨다(CTAP2 §12.7). 잘못된 인증 정보는 계속 실패한다. [`docs/ctap2-clientpin.md`](../docs/ctap2-clientpin.md), [`docs/ctap2-getassertion.md`](../docs/ctap2-getassertion.md)
MakeCredential과 GetAssertion request parser는 CTAP2 §8에 따라 처리기가 이해하지 못하는 map key를 무시한다. 이는 최상위 parameter map과 RP/user entity, credential parameter/descriptor, options, 일반 extension map에 적용한다. 지원하는 필드의 중복이나 잘못된 값은 계속 거부한다. 최상위 command parameter 누락은 `MissingParameter`를 반환하며, RP/user entity·credential parameter·descriptor 구조의 필수 member 누락은 CTAP2 §8 권고에 따라 `CborUnexpectedType`를 반환한다. `hmac-secret` input map은 별도 문서화된 parser 규칙을 따른다.

`MakeCredentialRequest`는 CBOR 필수 필드, RP/user entity, ordered public-key algorithm, excludeList 및 등록 옵션을 검증한다. 최상위 필수 parameter 누락과 중첩 entity/credential parameter의 필수 member 누락을 서로 다른 CTAP status로 응답한다. excludeList는 RP hash로만 조회하고 일치 시 local presence interaction 후 `CredentialExcluded`를 응답한다. 등록 흐름은 승인 후 보호 키를 만들고 key reference, 보호 정보, user handle 및 선택적 user labels를 credential store에 넣는다. 암호화된 SQLite 저장소는 v1/v2 payload를 v3으로 원자적으로 마이그레이션하고 credential 생성 순서를 저장한다. 재시작 후 사용하려면 아직 OS 기반 `CredentialProtector` provider가 필요하다. [`docs/ctap2-makecredential.md`](../docs/ctap2-makecredential.md)

`authenticatorLargeBlobs` (`0x0c`)는 보호된 SQLite 저장소의 LargeBlobs array를 읽고 순차 조각으로 교체한다. 모든 쓰기 조각은 채널별 휘발 상태에서 조립하며 선언된 길이와 SHA-256 prefix를 검증한 후에만 원자적으로 저장한다. PIN/UV가 설정되었거나 `alwaysUv`이면 선택된 protocol의 `pinUvAuthParam`과 `lbw` permission을 요구한다. GetInfo는 저장소가 사용 가능하고 reset 중이 아닐 때만 `largeBlobs`와 65536-byte capacity를 광고한다. reset은 credentials/PIN과 같은 보호된 transaction에서 배열을 초기 값으로 되돌린다. Discoverable credential은 per-credential `largeBlobKey`를 보호 저장하고 MakeCredential response의 `0x05` 및 GetAssertion response의 `0x07` field로 반환한다. `credBlob`은 discoverable credential에 최대 32-byte opaque 값을 protected credential record에 저장하며, MakeCredential/GetAssertion의 signed authenticator-data extension으로 결과를 전달한다. GetInfo는 `credBlob`, `credProtect`, `maxCredBlobLength` (`0x0f`)를 함께 광고한다. [`docs/ctap2-largeblobs.md`](../docs/ctap2-largeblobs.md), [`docs/ctap2-largeblob-key.md`](../docs/ctap2-largeblob-key.md), [`docs/ctap2-credblob.md`](../docs/ctap2-credblob.md)

`authenticatorConfig` supports CTAP 2.2 `setMinPINLength` (`0x03`) with protected persistence, `acfg` authorization, an eight-RP dynamic allowlist, forced PIN change when required, GetInfo capability fields, and the signed `minPinLength` MakeCredential extension. Reset restores the default minimum and clears the dynamic list and force-change state. PIN complexity policy and enterprise attestation remain unsupported. [`docs/ctap2-clientpin.md`](../docs/ctap2-clientpin.md), [`docs/ctap2-makecredential.md`](../docs/ctap2-makecredential.md)

`KeyStore::create_signing_key`는 opaque reference와 protection metadata에 더해 ES256 public coordinates를 반환한다. Windows CNG는 public ECC blob만 export하고 private key는 provider 내부에 유지한다. macOS는 기본 Secure Enclave 키와 명시적 동의 이후의 software key를 Data Protection Keychain에 생성하고 P1363 서명을 반환한다. Linux는 기본 hardware-only 정책에서 실패하며 명시적 동의 이후에만 Secret Service software key를 생성한다. 실제 Secure Enclave 가용성은 signed app과 대상 기기에서 검증해야 한다. [`docs/key-store-public-keys.md`](../docs/key-store-public-keys.md), [`docs/macos-key-storage.md`](../docs/macos-key-storage.md), [`docs/linux-key-storage.md`](../docs/linux-key-storage.md)

MakeCredential 성공 응답은 `fmt: none` attestation object와 RP hash·UP/AT flags·AAGUID·credential ID·ES256 COSE key를 포함한 authenticator data를 인코딩한다. 이는 제조사 attestation이나 하드웨어 provenance를 주장하지 않는다. [`docs/ctap2-makecredential.md`](../docs/ctap2-makecredential.md)

MakeCredential 실행은 알고리즘·옵션 검사, RP-scoped excludeList presence check, 명시적 등록 승인, 보호 키 생성, metadata 기록과 응답 encoding을 연결한다. 등록 실패 뒤 생성한 키는 제거하며 credential debug 출력에서 ID·RP hash·user handle·key reference를 숨긴다. Tauri는 암호화된 persistent credential store를 앱 수명 동안 유지한다. [`docs/ctap2-makecredential.md`](../docs/ctap2-makecredential.md), [`docs/credential-store.md`](../docs/credential-store.md)

Credential domain은 private key bytes 대신 opaque key handle만 보관하고, 모든 allow-list/discoverable 조회를 RP ID hash로 격리한다. 중복 credential ID와 빈 metadata는 등록 전에 거부한다. Windows credential metadata는 current-user DPAPI, Linux는 Secret Service, macOS는 기본 Keychain에 보관한 key와 플랫폼별 associated data로 보호한다. Linux와 macOS는 공통 bounded AES-256-GCM envelope를 사용한다. Tauri는 앱 시작 시 persistent store를 초기화하고 승인 요청을 UI에 전달한다. 데스크톱 HID runtime과 CTAPHID service의 코드 연결은 위에 설명했으며, 실제 target OS 장치 통신과 browser WebAuthn 호환성은 별도 검증 항목이다. [`docs/credential-domain.md`](../docs/credential-domain.md), [`docs/windows-credential-protection.md`](../docs/windows-credential-protection.md), [`docs/linux-credential-protection.md`](../docs/linux-credential-protection.md), [`docs/macos-credential-protection.md`](../docs/macos-credential-protection.md), [`docs/desktop-approval-flow.md`](../docs/desktop-approval-flow.md)

GetAssertion에서 빈 allow-list는 present 상태로 유지되어 어떤 credential도 일치하지 않으며 `NoCredentials`를 반환한다. absent allow-list만 discoverable credential 조회를 허용한다. 플랫폼은 빈 allow-list를 보내지 않아야 한다. [`docs/ctap2-getassertion.md`](../docs/ctap2-getassertion.md)

프로그램은 지원 OS에서 가상 HID 장치의 연결과 분리를 제어하고, 사용자가 별도의 하드웨어 보안 키 없이 표준 WebAuthn 인증을 시도할 수 있는 환경을 제공하는 것을 목표로 한다. 각 OS와 브라우저 조합은 실제 검증을 통과한 경우에만 지원한다.

이 프로젝트의 핵심은 **USB 장치의 물리적 존재를 구현하는 것이 아니라, USB FIDO2 인증기의 표준 인터페이스와 인증 동작을
소프트웨어로 구현하는 것**이다.
