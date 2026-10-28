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
};

type ApprovalPrompt = {
  requestId: string;
  relyingPartyId: string;
  relyingPartyName: string | null;
  action: string;
  timeoutMillis: number;
};

function App() {
  const [status, setStatus] = useState<PlatformStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvalRequests, setApprovalRequests] = useState<ApprovalPrompt[]>([]);
  const [approvalError, setApprovalError] = useState<string | null>(null);

  useEffect(() => {
    if (!isTauri()) {
      setError("상태 정보는 데스크톱 앱에서 확인할 수 있습니다.");
      return;
    }

    void invoke<PlatformStatus>("platform_status")
      .then(setStatus)
      .catch(() => setError("백엔드 상태를 불러오지 못했습니다."));
  }, []);

  useEffect(() => {
    if (!isTauri()) return;

    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<ApprovalPrompt>("approval-request", ({ payload }) => {
      setApprovalRequests((current) => [
        ...current.filter((request) => request.requestId !== payload.requestId),
        payload,
      ]);
    })
      .then((stopListening) => {
        if (disposed) stopListening();
        else unlisten = stopListening;
      })
      .catch(() => setApprovalError("Could not receive approval requests."));

    return () => {
      disposed = true;
      unlisten?.();
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
                  : status?.virtualHidAvailable
                    ? "연결 대기"
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
          <p>이 개발 버전은 실제 보안 키를 만들거나 인증 요청에 응답하지 않습니다.</p>
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
