import { type FormEvent, useEffect, useRef, useState } from "react";
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
  desktopApprovalStatus: string;
  clientPinStatus: string;
  nativeUserVerificationStatus: string;
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

type ApprovalRequest = ApprovalPrompt & {
  deadlineAt: number;
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

function isActionCancelled(cause: unknown) {
  return cause === "Action cancelled by the user.";
}

function App() {
  const [status, setStatus] = useState<PlatformStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvalRequests, setApprovalRequests] = useState<ApprovalRequest[]>([]);
  const [approvalCountdownNow, setApprovalCountdownNow] = useState(() => performance.now());
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [respondingRequests, setRespondingRequests] = useState<Set<string>>(() => new Set());
  const [runtimeAction, setRuntimeAction] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [showCredentials, setShowCredentials] = useState(false);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const [resetAction, setResetAction] = useState(false);
  const [pinAction, setPinAction] = useState(false);
  const [pinError, setPinError] = useState<string | null>(null);
  const [pinMessage, setPinMessage] = useState<string | null>(null);
  const [showDiagnosticLog, setShowDiagnosticLog] = useState(false);
  const [diagnosticLog, setDiagnosticLog] = useState<string | null>(null);
  const [diagnosticLogError, setDiagnosticLogError] = useState<string | null>(null);
  const [diagnosticLogLoading, setDiagnosticLogLoading] = useState(false);
  const currentPinRef = useRef<HTMLInputElement>(null);
  const newPinRef = useRef<HTMLInputElement>(null);
  const confirmPinRef = useRef<HTMLInputElement>(null);

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

  const loadDiagnosticLog = async () => {
    setDiagnosticLogLoading(true);
    setDiagnosticLogError(null);
    try {
      setDiagnosticLog(await invoke<string>("read_diagnostic_log"));
    } catch {
      setDiagnosticLog(null);
      setDiagnosticLogError("Redacted diagnostic events are unavailable.");
    } finally {
      setDiagnosticLogLoading(false);
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
    if (showCredentials && !status?.authenticatorRunning && status?.credentialStoreAvailable) {
      void loadCredentials();
    }
  }, [showCredentials, status?.authenticatorRunning, status?.hostPlatform]);

  useEffect(() => {
    if (!isTauri()) return;

    let disposed = false;
    let unlistenApproval: (() => void) | undefined;
    let unlistenCancelled: (() => void) | undefined;
    void listen<ApprovalPrompt>("approval-request", ({ payload }) => {
      const receivedAt = performance.now();
      setApprovalCountdownNow(receivedAt);
      setApprovalRequests((current) => [
        ...current.filter((request) => request.requestId !== payload.requestId),
        { ...payload, deadlineAt: receivedAt + payload.timeoutMillis },
      ]);
    })
      .then((stopListening) => {
        if (disposed) stopListening();
        else unlistenApproval = stopListening;
      })
      .catch(() => setApprovalError("Could not receive approval requests."));

    void listen<string>("approval-cancelled", ({ payload: requestId }) => {
      setApprovalRequests((current) => current.filter((request) => request.requestId !== requestId));
      setRespondingRequests((current) => {
        if (!current.has(requestId)) return current;
        const next = new Set(current);
        next.delete(requestId);
        return next;
      });
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

  useEffect(() => {
    if (approvalRequests.length === 0) return;
    const interval = window.setInterval(
      () => setApprovalCountdownNow(performance.now()),
      1000,
    );
    return () => window.clearInterval(interval);
  }, [approvalRequests.length]);

  const respondToApproval = (requestId: string, approved: boolean) => {
    if (respondingRequests.has(requestId)) return;
    setApprovalError(null);
    setRespondingRequests((current) => new Set(current).add(requestId));
    void invoke("respond_approval", { requestId, approved })
      .then(() => {
        setApprovalRequests((current) => current.filter((request) => request.requestId !== requestId));
      })
      .catch(() => setApprovalError("That approval request has expired or is no longer active."))
      .finally(() => {
        setRespondingRequests((current) => {
          const next = new Set(current);
          next.delete(requestId);
          return next;
        });
      });
  };

  const startAuthenticator = async () => {
    setRuntimeAction(true);
    setRuntimeError(null);
    try {
      await invoke("start_authenticator");
      await refreshStatus();
    } catch (cause) {
      if (isActionCancelled(cause)) return;
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

  const submitClientPin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPinError(null);
    setPinMessage(null);
    const newPin = newPinRef.current?.value ?? "";
    const confirmation = confirmPinRef.current?.value ?? "";
    if (newPin !== confirmation) {
      setPinError("새 PIN과 확인 값이 일치하지 않습니다.");
      confirmPinRef.current?.focus();
      return;
    }
    const currentPin = status?.clientPinStatus === "Configured"
      ? currentPinRef.current?.value ?? ""
      : null;
    setPinAction(true);
    try {
      await invoke("set_client_pin", { currentPin, newPin });
      setPinMessage("인증기 PIN을 업데이트했습니다.");
      await refreshStatus();
    } catch (cause) {
      if (!isActionCancelled(cause)) {
        setPinError(typeof cause === "string" ? cause : "인증기 PIN을 업데이트하지 못했습니다.");
      }
    } finally {
      if (currentPinRef.current) currentPinRef.current.value = "";
      if (newPinRef.current) newPinRef.current.value = "";
      if (confirmPinRef.current) confirmPinRef.current.value = "";
      setPinAction(false);
    }
  };

  const deleteCredential = async (credential: CredentialSummary) => {
    setCredentialError(null);
    try {
      await invoke("delete_credential", { creationOrder: credential.creationOrder });
      await loadCredentials();
    } catch (cause) {
      if (isActionCancelled(cause)) return;
      await loadCredentials();
      setCredentialError(typeof cause === "string" ? cause : "자격 증명을 삭제하지 못했습니다.");
    }
  };

  const resetCredentials = async () => {
    setResetAction(true);
    setCredentialError(null);
    try {
      await invoke<number>("reset_credentials");
      await loadCredentials();
    } catch (cause) {
      if (isActionCancelled(cause)) return;
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
        <p className="intro">가상 FIDO HID 백엔드와 이 컴퓨터의 준비 상태를 확인합니다. 브라우저 WebAuthn 상호운용성은 아직 검증되지 않았으며, 현재 지원이 선언된 OS·브라우저 조합은 없습니다. 검증 현황은 저장소의 docs/support-matrix.md에서 확인할 수 있습니다.</p>

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
                    ? "HID 백엔드 준비됨"
                    : "HID 백엔드 사용 불가"}
              </h2>
            </div>
            <span className={`status-pill ${status?.virtualHidAvailable ? "pill-ready" : "pill-pending"}`}>
              {status?.virtualHidAvailable ? "백엔드 준비" : "백엔드 미준비"}
            </span>
          </div>
          <p className="status-message">
            {error ?? status?.statusMessage ?? "시스템 상태를 확인하고 있습니다…"}
          </p>
          {isTauri() && status && ["Linux", "Windows", "macOS"].includes(status.hostPlatform) && !status.authenticatorRunning && status.virtualHidAvailable && status.credentialStoreAvailable && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={() => void startAuthenticator()}>
                {runtimeAction ? "시작 중…" : "인증기 시작"}
              </button>
            </div>
          )}
          {isTauri() && status?.authenticatorRunning && (
            <div className="runtime-actions">
              <button type="button" disabled={runtimeAction} onClick={stopAuthenticator}>인증기 중지</button>
            </div>
          )}
          {runtimeError && <p className="status-message" role="alert">{runtimeError}</p>}
          {isTauri() && status?.credentialStoreAvailable && (
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
              <dt>요청 승인 방식</dt>
              <dd>{status?.desktopApprovalStatus ?? "확인 중"}</dd>
            </div>
            <div>
              <dt>인증기 PIN</dt>
              <dd>{status?.clientPinStatus ?? "확인 중"}</dd>
            </div>
            <div>
              <dt>운영체제 사용자 확인</dt>
              <dd>{status?.nativeUserVerificationStatus ?? "확인 중"}</dd>
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
          {isTauri() && status?.credentialStoreAvailable && !status.authenticatorRunning &&
            (status.clientPinStatus === "Configured" || status.clientPinStatus === "Not configured") && (
            <form className="pin-settings" onSubmit={(event) => void submitClientPin(event)}>
              <h2>{status.clientPinStatus === "Configured" ? "인증기 PIN 변경" : "인증기 PIN 설정"}</h2>
              {status.clientPinStatus === "Configured" && (
                <label>
                  현재 PIN
                  <input ref={currentPinRef} type="password" autoComplete="off" required disabled={pinAction} />
                </label>
              )}
              <label>
                새 PIN
                <input ref={newPinRef} type="password" autoComplete="off" minLength={4} required disabled={pinAction} />
              </label>
              <label>
                새 PIN 확인
                <input ref={confirmPinRef} type="password" autoComplete="off" minLength={4} required disabled={pinAction} />
              </label>
              <p className="pin-policy">최소 4개의 Unicode 코드 포인트, UTF-8 기준 최대 63바이트입니다. 보호된 저장소에 PIN 검증값만 저장됩니다.</p>
              <div className="runtime-actions">
                <button type="submit" disabled={pinAction}>{pinAction ? "저장 중…" : "PIN 저장"}</button>
              </div>
              {pinError && <p role="alert" className="pin-result is-error">{pinError}</p>}
              {pinMessage && <p role="status" className="pin-result">{pinMessage}</p>}
            </form>
          )}
        </div>

        {showCredentials && status?.credentialStoreAvailable && (
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
            {approvalRequests.map((request) => {
              const responding = respondingRequests.has(request.requestId);
              const secondsRemaining = Math.max(
                0,
                Math.ceil((request.deadlineAt - approvalCountdownNow) / 1000),
              );
              return (
                <article className="approval-card" key={request.requestId}>
                <p className="eyebrow">Approval required</p>
                <h2>{request.action}</h2>
                <p className="approval-rp">
                  {request.relyingPartyName ?? request.relyingPartyId}
                  {request.relyingPartyName && <span> ({request.relyingPartyId})</span>}
                </p>
                <p className="approval-timeout">
                  {secondsRemaining > 0
                    ? `This request expires in ${secondsRemaining} seconds.`
                    : "This request expired. Waiting for the authenticator to close it."}
                </p>
                <p className="approval-timeout">
                  Approving here opens a native confirmation dialog before signing.
                </p>
                <div className="approval-actions">
                  <button type="button" disabled={responding} onClick={() => respondToApproval(request.requestId, false)}>
                    Deny
                  </button>
                  <button type="button" disabled={responding} onClick={() => respondToApproval(request.requestId, true)}>
                    {responding ? "Confirming…" : "Approve"}
                  </button>
                </div>
                </article>
              );
            })}
            {approvalError && <p className="status-message" role="alert">{approvalError}</p>}
          </section>
        )}

        <div className="notice" role="note">
          <span className="notice-icon" aria-hidden="true">i</span>
          <p>{status?.authenticatorRunning
            ? "인증기가 실행 중입니다. 자격 증명 생성과 인증은 각각 사용자 승인이 필요합니다."
            : status?.hostPlatform === "Windows"
              ? "Windows에서는 검증된 UDE 드라이버와 TPM 보호 키 저장소가 준비된 경우에만 인증기를 시작할 수 있습니다."
              : status?.hostPlatform === "macOS"
                ? "macOS 인증기를 시작하려면 할당된 제품 ID와 Apple의 서명된 HID entitlement가 필요합니다."
                : "Linux에서 인증기를 시작하려면 세션별 소프트웨어 키 사용 동의가 필요합니다."}</p>
        </div>
      </section>

      {isTauri() && (
        <section className="diagnostic-panel" aria-label="Redacted diagnostic events">
          <div className="credential-list-heading">
            <div>
              <p className="eyebrow">Local diagnostics</p>
              <h2>Redacted events</h2>
            </div>
            <div className="credential-list-actions">
              <button
                type="button"
                onClick={() => {
                  setShowDiagnosticLog(true);
                  void loadDiagnosticLog();
                }}
              >
                {showDiagnosticLog ? "Refresh" : "View events"}
              </button>
              {showDiagnosticLog && (
                <button type="button" onClick={() => setShowDiagnosticLog(false)}>
                  Hide
                </button>
              )}
            </div>
          </div>
          {showDiagnosticLog && (
            <>
              <p className="diagnostic-description">
                Fixed event codes and coarse outcomes only. Entries stay on this device.
              </p>
              {diagnosticLogLoading ? (
                <p className="status-message" role="status">Loading diagnostics…</p>
              ) : diagnosticLogError ? (
                <p className="status-message" role="status">{diagnosticLogError}</p>
              ) : (
                <pre className="diagnostic-log" aria-live="polite">
                  {diagnosticLog || "No diagnostic events have been recorded."}
                </pre>
              )}
            </>
          )}
        </section>
      )}

      <footer className="app-footer">
        <span>{status?.productName ?? "Ghost FIDO Key"} {status?.productVersion ?? "0.1.0"}</span>
        <span>로컬 상태만 표시합니다</span>
      </footer>
    </main>
  );
}

export default App;
