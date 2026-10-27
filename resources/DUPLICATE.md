# Init

기존 프로젝트들을 검색해 볼게요.

이미 꽤 많아요. 가상 USB로 인식시키는 방식은 크게 두 가지입니다.

## 1. USB/IP 방식 (진짜 가상 USB 장치로 붙임)

- **[bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido)**:
  가장 유명한 프로젝트예요. YubiKey처럼 FIDO2/U2F를 구현하는 가상 USB
  장치이고, USB/IP로 Windows와 Linux를 지원합니다. Go로 만들어졌어요.
  이 프로젝트 기반의 패스키 매니저(Bulwark Passkey)도 있어요.
- **[ellerh/softfido](https://www.github.com/ellerh/softfido)**:
  USBIP로 가상 USB 장치를 구현하고, 암호 연산은 SoftHSM에 맡기는 Rust
  프로젝트예요. 취미 프로젝트라고 밝히고 있어요.
- **[425384130/Virtual-FIDO2-For-WINDOWS](https://github.com/425384130/Virtual-FIDO2-For-WINDOWS)**:
  Windows 7~11을 지원하는 가상 USB FIDO2 장치예요.

## 2. UHID 방식 (Linux 커널의 가상 HID 장치, USB/IP보다 간단)

- **[pando85/passless](https://github.com/pando85/passless)**:
  Linux에서 가상 UHID 장치로 동작하는 소프트웨어 FIDO2 인증기예요.
  내부적으로 soft-fido2 라이브러리를 써요.
- **soft-fido2 (Rust 크레이트)**: CTAP 2.0/2.1/2.2 전체 구현에 USB HID와
  Linux UHID 전송 계층을 제공해서 라이브러리로 가져다 쓸 수 있어요.
- **[fidorium](https://docs.rs/fidorium)**:
  /dev/uhid로 가상 USB HID 인증기로 보이고, 키는 TPM 2.0에 저장해요.
- **soft-fido2 (Python, PyPI)**: Linux용 소프트웨어 패스키 인증기이고,
  UHID를 이용한 가상 USB 장치로 연동하거나 USB/IP를 대안으로 쓸 수
  있습니다.
- **[BryanJacobs/fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge)**:
  PC/SC 인증기(NFC, 스마트카드)의 명령을 가상 USB-HID 장치로 전달하는
  브리지예요. 소프트웨어 키 자체는 아니에요.

## 차별화 포인트

- Linux 외에 **Windows/macOS를 제대로 지원**하는 프로젝트는 드물어요
  (virtual-fido가 거의 유일).
- 키 저장을 **TPM / Secure Enclave / OS 키체인**에 묶는 건 fidorium 정도만
  있어요.
- 사용 편의(GUI, 트레이 앱, 승인 팝업)는 대부분 약해요.

이 중 하나와 겹치지 않는 방향으로 잡으면 `ghost-security-key`가 독자적인
프로젝트가 될 수 있어요. 어떤 OS를 타겟으로 하실지 알려주시면 방향을 더
좁혀 드릴게요.

Sources:

- [bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido)
- [ellerh/softfido](https://www.github.com/ellerh/softfido)
- [425384130/Virtual-FIDO2-For-WINDOWS](https://github.com/425384130/Virtual-FIDO2-For-WINDOWS)
- [passless (lib.rs)](https://lib.rs/crates/passless-rs)
- [soft-fido2 (docs.rs)](https://docs.rs/crate/soft-fido2/latest)
- [fidorium (docs.rs)](https://docs.rs/fidorium)
- [soft-fido2 (PyPI)](https://pypi.org/project/soft-fido2/0.3.8/)
- [BryanJacobs/fido2-hid-bridge](https://github.com/BryanJacobs/fido2-hid-bridge)
