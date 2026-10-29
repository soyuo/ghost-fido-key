import { useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type PlatformStatus = {
  productName: string;
  productVersion: string;
  hostPlatform: string;
  virtualHidAvailable: boolean;
  deviceAttached: boolean;
  keyStorageStatus: string;
  userVerificationStatus: string;
  credentialStoreAvailable: boolean;
  credentialStoreStatus: string;
  statusMessage: string;
  authenticatorRunning: boolean;
};

type ApprovalPrompt = {
  requestId: string;
  relyingPartyId: string;
  relyingPartyName: string | null;
  action: string;
  timeoutMillis: number;
};

type CredentialSummary = {
  creationOrder: number;
  relyingPartyId: string | null;
  userName: string | null;
  userDisplayName: string | null;
  keyProtection: string;
  exportable: boolean;
  discoverable: boolean;
};

function App() {
  const [status, setStatus] = useState<PlatformStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvalRequests, setApprovalRequests] = useState<ApprovalPrompt[]>([]);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [showSoftwareKeyWarning, setShowSoftwareKeyWarning] = useState(false);
  const [runtimeAction, setRuntimeAction] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [showCredentials, setShowCredentials] = useState(false);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const [resetAction, setResetAction] = useState(false);

  const refreshStatus = () => invoke<PlatformStatus>("platform_status").then(setStatus);
  const refreshCredentials = () => invoke<CredentialSummary[]>("list_credentials").then(setCredentials);
  const loadCredentials = async () => {
    try {
      await refreshCredentials();
      setCredentialError(null);
    } catch (cause) {
      setCredentialError(typeof cause === "string" ? cause : "자격 증명 목록을 불러오지 못했습니다.");
    }
  };

  useEffect(() => {
    if (!isTauri()) {
      setError("상태 정보는 데스크톱 앱에서 확인할 수 있습니다.");
      return;
    }

    void refreshStatus()
      .catch(() => setError("백엔드 상태를 불러오지 못했습니다."));
    const refreshTimer = window.setInterval(() => {
      void refreshStatus().catch(() => setError("백엔드 상태를 불러오지 못했습니다."));
    }, 1000);
    return () => window.clearInterval(refreshTimer);
  }, []);

  useEffect(() => {
    if (showCredentials && !status?.authenticatorRunning && status?.hostPlatform === "Linux") {
      void loadCredentials();
    }
  }, [showCredentials, status?.authenticatorRunning, status?.hostPlatform]);

  useEffect(() => {
    if (!isTauri()) return;

    let disposed = false;
    let unlistenApproval: (() => void) | undefined;
    let unlistenCancelled: (() => void) | undefined;
    void listen<ApprovalPrompt>("approval-request", ({ payload }) => {
      setApprovalRequests((current) => [
        ...current.filter((request) => request.requestId !== payload.requestId),
        payload,
      ]);
    })
      .then((stopListening) => {
        if (disposed) stopListening();
        else unlistenApproval = stopListening;
      })
      .catch(() => setApprovalError("Could not receive approval requests."));

    void listen<string>("approval-cancelled", ({ payload: requestId }) => {
      setApprovalRequests((current) => current.filter((request) => request.requestId !== requestId));
    })
      .then((stopListening) => {
        if (disposed) stopListening();
        else unlistenCancelled = stopListening;
      })
      .catch(() => setApprovalError("Could not receive approval cancellation updates."));

    return () => {
      disposed = true;
      unlistenApproval?.();
      unlistenCancelled?.();
    };
  }, []);

  const respondToApproval = (requestId: string, approved: boolean) => {
    setApprovalError(null);
    void invoke("respond_approval", { requestId, approved })
      .then(() => {
        setApprovalRequests((current) => current.filter((request) => request.requestId !== requestId));
      })
      .catch(() => setApprovalError("That approval request has expired or is no longer active."));
  };

  const startAuthenticator = async (softwareKeyRiskAcknowledged: boolean) => {
    setRuntimeAction(true);
    setRuntimeError(null);
    try {
      await invoke("start_authenticator", { softwareKeyRiskAcknowledged });
      setShowSoftwareKeyWarning(false);
      await refreshStatus();
    } catch (cause) {
      setRuntimeError(typeof cause === "string" ? cause : "인증기를 시작하지 못했습니다. 가상 HID 권한과 키 저장소 상태를 확인하세요.");
    } finally {
      setRuntimeAction(false);
    }
  };

  const stopAuthenticator = async () => {
    setRuntimeAction(true);
    setRuntimeError(null);
    try {
      await invoke("stop_authenticator");
      await refreshStatus();
    } catch (cause) {
      setRuntimeError(typeof cause === "string" ? cause : "인증기를 정상적으로 중지하지 못했습니다.");
    } finally {
      setRuntimeAction(false);
    }
  };

  const deleteCredential = async (credential: CredentialSummary) => {
    const site = credential.relyingPartyId ?? "사이트를 확인할 수 없는 기존 자격 증명";
    const user = credential.userDisplayName ?? credential.userName;
    if (!window.confirm(`${site}${user ? `\n${user}` : ""} 자격 증명을 삭제할까요? 이 작업은 되돌릴 수 없습니다.`)) return;

    setCredentialError(null);
    try {
      await invoke("delete_credential", { creationOrder: credential.creationOrder, confirmed: true });
      await loadCredentials();
    } catch (cause) {
      await loadCredentials();
      setCredentialError(typeof cause === "string" ? cause : "자격 증명을 삭제하지 못했습니다.");
    }
  };

  const resetCredentials = async () => {
    if (!window.confirm("이 컴퓨터에 저장된 모든 credential과 signing key를 삭제합니다. 이 작업은 되돌릴 수 없습니다.")) return;
    if (window.prompt("확인을 위해 RESET을 입력하세요.") !== "RESET") return;

    setResetAction(true);
    setCredentialError(null);
    try {
      await invoke<number>("reset_credentials", { confirmed: true });
      await loadCredentials();
    } catch (cause) {
      await loadCredentials();
      setCredentialError(typeof cause === "string" ? cause : "인증기 자격 증명을 초기화하지 못했습니다.");
    } finally {
      setResetAction(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="Ghost FIDO Key 홈">
          <span className="brand-mark" aria-hidden="true">G</span>
          <span>Ghost FIDO Key</span>
        </a>
        <span className="version">초기 개발 버전</span>
      </header>

      <section className="hero" aria-labelledby="page-title">
        <p className="eyebrow">가상 인증기</p>
        <h1 id="page-title">보안 키 상태</h1>
        <p className="intro">가상 FIDO 인증기의 연결 상태와 이 컴퓨터의 준비 상태를 확인합니다.</p>

        <div className="status-card" aria-live="polite" aria-busy={!status && !error}>
          <div className="status-heading">
            <span className={`status-dot ${status?.virtualHidAvailable ? "is-ready" : "is-pending"}`} aria-hidden="true" />
            <div>
              <p className="status-label">가상 인증기</p>
              <h2>
                {status?.deviceAttached
                  ? "연결됨"
                  : status?.authenticatorRunning
                    ? "연결 중"
                  : status?.virtualHidAvailable && status?.hostPlatform === "Linux"
                    ? "연결 대기"
                    : status?.virtualHidAvailable
                      ? "사용 준비됨"
                    : "사용할 수 없음"}
              </h2>
            </div>
            <span className={`status-pill ${status?.virtualHidAvailable ? "pill-ready" : "pill-pending"}`}>
              {status?.virtualHidAvailable ? "준비됨" : "개발 중"}
            </span>
          </div>
          <p className="status-message">
            {error ?? status?.statusMessage ?? "시스템 상태를 확인하고 있습니다…"}
          </p>
          {isTauri() && status?.hostPlatform === "Linux" && !status.authenticatorRunning && status.virtualHidAvailable && status.credentialStoreAvailable && !showSoftwareKeyWarning && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={() => setShowSoftwareKeyWarning(true)}>
                인증기 시작
              </button>
            </div>
          )}
          {isTauri() && status?.hostPlatform === "Windows" && !status.authenticatorRunning && status.virtualHidAvailable && status.credentialStoreAvailable && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={() => void startAuthenticator(false)}>
                {runtimeAction ? "시작 중…" : "인증기 시작"}
              </button>
            </div>
          )}
          {isTauri() && status?.hostPlatform === "macOS" && !status.authenticatorRunning && status.virtualHidAvailable && status.credentialStoreAvailable && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={() => void startAuthenticator(false)}>
                {runtimeAction ? "시작 중…" : "인증기 시작"}
              </button>
            </div>
          )}
          {isTauri() && status?.authenticatorRunning && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={stopAuthenticator}>인증기 중지</button>
            </div>
          )}
          {showSoftwareKeyWarning && (
            <section className="software-key-warning" aria-labelledby="software-key-title">
              <p className="eyebrow">보안 확인</p>
              <h2 id="software-key-title">소프트웨어 보안 키 사용</h2>
              <p>개인 키는 하드웨어 보안 모듈이 아닌 소프트웨어로 생성되며 Linux Secret Service에 저장됩니다. 보호 수준은 Secret Service 설정에 따르고, 해당 계정이나 저장소에 접근할 수 있는 사용자가 키를 추출할 수 있습니다.</p>
              <p>동의하면 이번 앱 실행 세션에서만 소프트웨어 키 생성을 허용합니다.</p>
              <div className="approval-actions">
                <button type="button" disabled={runtimeAction} onClick={() => setShowSoftwareKeyWarning(false)}>취소</button>
                <button type="button" disabled={runtimeAction} onClick={() => void startAuthenticator(true)}>{runtimeAction ? "시작 중…" : "위험을 이해했고 시작"}</button>
              </div>
            </section>
          )}
          {runtimeError && <p className="status-message" role="alert">{runtimeError}</p>}
          {isTauri() && status?.hostPlatform === "Linux" && status.credentialStoreAvailable && (
            <div className="runtime-actions">
              <button
                type="button"
                disabled={status.authenticatorRunning}
                onClick={() => setShowCredentials((visible) => !visible)}
              >
                {showCredentials ? "자격 증명 숨기기" : "등록된 자격 증명 관리"}
              </button>
            </div>
          )}
          <div className="card-divider" />
          <dl className="details">
            <div>
              <dt>운영체제</dt>
              <dd>{status?.hostPlatform ?? "확인 중"}</dd>
            </div>
            <div>
              <dt>장치 연결</dt>
              <dd>{status?.deviceAttached ? "연결됨" : "연결 안 됨"}</dd>
            </div>
            <div>
              <dt>보안 키 보호</dt>
              <dd>{status?.keyStorageStatus ?? "확인 중"}</dd>
            </div>
            <div>
              <dt>사용자 확인</dt>
              <dd>{status?.userVerificationStatus ?? "확인 중"}</dd>
            </div>
          </dl>
          <p
            className="status-message"
            role="status"
            aria-label={
              status?.credentialStoreAvailable
                ? "Credential storage available"
                : "Credential storage unavailable"
            }
          >
            {status?.credentialStoreStatus ?? "Credential storage status is unavailable."}
          </p>
        </div>

        {showCredentials && status?.hostPlatform === "Linux" && (
          <section className="credential-list" aria-label="등록된 자격 증명">
            <div className="credential-list-heading">
              <div>
                <p className="eyebrow">Credential management</p>
                <h2>등록된 자격 증명</h2>
              </div>
              <div className="credential-list-actions">
                <button type="button" disabled={status.authenticatorRunning || resetAction} onClick={() => void loadCredentials()}>
                  새로고침
                </button>
                <button type="button" className="credential-reset" disabled={status.authenticatorRunning || resetAction} onClick={() => void resetCredentials()}>
                  {resetAction ? "초기화 중…" : "모든 자격 증명 초기화"}
                </button>
              </div>
            </div>
            {credentialError && <p className="status-message" role="alert">{credentialError}</p>}
            {credentials.length === 0 ? (
              <p className="credential-empty">등록된 자격 증명이 없습니다.</p>
            ) : credentials.map((credential) => (
              <article className="credential-card" key={credential.creationOrder}>
                <div>
                  <h3>{credential.relyingPartyId ?? "알 수 없는 사이트 (기존 자격 증명)"}</h3>
                  {(credential.userDisplayName || credential.userName) && (
                    <p>{credential.userDisplayName ?? credential.userName}</p>
                  )}
                  <p className="credential-meta">
                    {credential.keyProtection}{credential.exportable ? " · 추출 가능" : " · 추출 불가"}
                    {credential.discoverable ? " · discoverable" : " · allow-list 전용"}
                  </p>
                </div>
                <button type="button" className="credential-delete" disabled={status.authenticatorRunning} onClick={() => void deleteCredential(credential)}>
                  삭제
                </button>
              </article>
            ))}
          </section>
        )}

        {approvalRequests.length > 0 && (
          <section className="approval-list" aria-label="Pending authenticator approvals">
            {approvalRequests.map((request) => (
              <article className="approval-card" key={request.requestId}>
                <p className="eyebrow">Approval required</p>
                <h2>{request.action}</h2>
                <p className="approval-rp">
                  {request.relyingPartyName ?? request.relyingPartyId}
                  {request.relyingPartyName && <span> ({request.relyingPartyId})</span>}
                </p>
                <p className="approval-timeout">
                  This request expires in {Math.ceil(request.timeoutMillis / 1000)} seconds.
                </p>
                <div className="approval-actions">
                  <button type="button" onClick={() => respondToApproval(request.requestId, false)}>
                    Deny
                  </button>
                  <button type="button" onClick={() => respondToApproval(request.requestId, true)}>
                    Approve
                  </button>
                </div>
              </article>
            ))}
            {approvalError && <p className="status-message" role="alert">{approvalError}</p>}
          </section>
        )}

        <div className="notice" role="note">
          <span className="notice-icon" aria-hidden="true">i</span>
          <p>{status?.authenticatorRunning
            ? "인증기가 실행 중입니다. 자격 증명 생성과 인증은 각각 사용자 승인이 필요합니다."
            : status?.hostPlatform === "Windows"
              ? "Windows에서는 검증된 UDE 드라이버와 TPM 보호 키 저장소가 준비된 경우에만 인증기를 시작할 수 있습니다."
              : "Linux에서 인증기를 시작하려면 세션별 소프트웨어 키 사용 동의가 필요합니다."}</p>
        </div>
      </section>

      <footer className="app-footer">
        <span>{status?.productName ?? "Ghost FIDO Key"} {status?.productVersion ?? "0.1.0"}</span>
        <span>로컬 상태만 표시합니다</span>
      </footer>
    </main>
  );
}

export default App;
