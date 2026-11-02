import { type FormEvent, useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Badge,
  Button,
  Card,
  Heading,
  ListRow,
  SegmentedControl,
  Text,
  TextField,
} from "@zaemoru/react";
import "./App.css";

type Theme = "light" | "dark";
type FieldElement = HTMLElement & { value: string };

const THEME_STORAGE_KEY = "ghost-fido-theme";

function initialTheme(): Theme {
  return localStorage.getItem(THEME_STORAGE_KEY) === "dark" ? "dark" : "light";
}

type PlatformStatus = {
  productName: string;
  productVersion: string;
  hostPlatform: string;
  virtualHidAvailable: boolean;
  virtualHidCanStart: boolean;
  deviceAttached: boolean;
  keyStorageStatus: string;
  desktopApprovalStatus: string;
  clientPinStatus: string;
  nativeUserVerificationStatus: string;
  credentialStoreAvailable: boolean;
  credentialStoreStatus: string;
  authenticatorResetPending: boolean;
  providerKeyCleanupPending: boolean;
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
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const currentPinRef = useRef<FieldElement>(null);
  const newPinRef = useRef<FieldElement>(null);
  const confirmPinRef = useRef<FieldElement>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

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

  const submitClientPin = async (event?: FormEvent<HTMLFormElement>) => {
    event?.preventDefault();
    setPinError(null);
    setPinMessage(null);
    const newPin = newPinRef.current?.value ?? "";
    const confirmation = confirmPinRef.current?.value ?? "";
    if ([...newPin].length < 4) {
      setPinError("새 PIN은 최소 4자 이상이어야 합니다.");
      newPinRef.current?.focus();
      return;
    }
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
      await refreshStatus();
    } catch (cause) {
      if (isActionCancelled(cause)) return;
      await loadCredentials();
      await refreshStatus();
      setCredentialError(typeof cause === "string" ? cause : "인증기 자격 증명을 초기화하지 못했습니다.");
    } finally {
      setResetAction(false);
    }
  };

  const statusTitle = status?.deviceAttached
    ? status.virtualHidAvailable ? "연결됨" : "런타임 연결됨 · 지원 검증 대기"
    : status?.authenticatorRunning
      ? "연결 중"
      : status?.virtualHidAvailable && status?.hostPlatform === "Linux"
        ? "연결 대기"
        : status?.virtualHidAvailable
          ? "HID 백엔드 준비됨"
          : "HID 백엔드 사용 불가";
  const statusBadge = status?.virtualHidAvailable
    ? "백엔드 준비"
    : status?.virtualHidCanStart ? "구성됨 · 검증 대기" : "백엔드 미준비";
  const details: [string, string][] = [
    ["운영체제", status?.hostPlatform ?? "확인 중"],
    ["장치 연결", status?.deviceAttached ? "연결됨" : "연결 안 됨"],
    ["보안 키 보호", status?.keyStorageStatus ?? "확인 중"],
    ["요청 승인 방식", status?.desktopApprovalStatus ?? "확인 중"],
    ["인증기 PIN", status?.clientPinStatus ?? "확인 중"],
    ["운영체제 사용자 확인", status?.nativeUserVerificationStatus ?? "확인 중"],
  ];
  const canStart = isTauri() && !!status && ["Linux", "Windows", "macOS"].includes(status.hostPlatform)
    && !status.authenticatorRunning && status.virtualHidCanStart && status.credentialStoreAvailable;
  const showRuntimeActions = isTauri()
    && (canStart || !!status?.authenticatorRunning || !!status?.credentialStoreAvailable);

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="Ghost FIDO Key 홈">
          <span className="brand-mark" aria-hidden="true">G</span>
          <span>Ghost FIDO Key</span>
          <Badge variant="weak" size="xsmall" color="elephant">초기 개발 버전</Badge>
        </a>
        <SegmentedControl
          className="theme-toggle"
          options={[
            { value: "light", label: "라이트" },
            { value: "dark", label: "다크" },
          ]}
          value={theme}
          onChange={(value) => setTheme(value === "dark" ? "dark" : "light")}
        />
      </header>

      <main className="content">
        <section className="hero" aria-labelledby="page-title">
          <Text size="sm" weight="semibold" tone="primary">가상 인증기</Text>
          <Heading level="1" size="3xl" id="page-title">보안 키 상태</Heading>
          <Text tone="subtle" className="intro">
            가상 FIDO HID 백엔드와 이 컴퓨터의 준비 상태를 확인합니다. 브라우저 WebAuthn 상호운용성은 아직 검증되지 않았으며, 현재 지원이 선언된 OS·브라우저 조합은 없습니다. 검증 현황은 저장소의 docs/support-matrix.md에서 확인할 수 있습니다.
          </Text>
        </section>

        {approvalRequests.length > 0 && (
          <section className="stack" aria-label="Pending authenticator approvals">
            {approvalRequests.map((request) => {
              const responding = respondingRequests.has(request.requestId);
              const secondsRemaining = Math.max(
                0,
                Math.ceil((request.deadlineAt - approvalCountdownNow) / 1000),
              );
              return (
                <Card key={request.requestId} elevation="medium" padding="large" className="approval-card">
                  <div className="stack">
                    <div className="card-heading">
                      <div>
                        <Text size="sm" weight="semibold" tone="primary">Approval required</Text>
                        <Heading level="2" size="xl">{request.action}</Heading>
                      </div>
                      <Badge variant="fill" size="small" color={secondsRemaining > 0 ? "blue" : "elephant"}>
                        {secondsRemaining > 0 ? `${secondsRemaining}s` : "만료"}
                      </Badge>
                    </div>
                    <Text weight="medium">
                      {request.relyingPartyName ?? request.relyingPartyId}
                      {request.relyingPartyName && <span className="muted"> ({request.relyingPartyId})</span>}
                    </Text>
                    {request.action === "Use software key" && (
                      <p className="callout is-danger" role="alert">
                        The hardware-protected key could not be created. Approving creates this credential with a software-backed key instead, which may be less resistant if this device or account storage is compromised. Denying cancels credential registration.
                      </p>
                    )}
                    <Text size="sm" tone="muted">
                      {secondsRemaining > 0
                        ? `This request expires in ${secondsRemaining} seconds.`
                        : "This request expired. Waiting for the authenticator to close it."}
                      {" "}Approving here opens a native confirmation dialog before signing.
                    </Text>
                    <div className="actions">
                      <Button variant="secondary" disabled={responding} onClick={() => respondToApproval(request.requestId, false)}>
                        Deny
                      </Button>
                      <Button variant="primary" loading={responding} disabled={responding} onClick={() => respondToApproval(request.requestId, true)}>
                        Approve
                      </Button>
                    </div>
                  </div>
                </Card>
              );
            })}
            {approvalError && <p className="callout is-danger" role="alert">{approvalError}</p>}
          </section>
        )}

        <Card elevation="low" padding="large">
          <div className="stack">
            <div className="stack" aria-live="polite" aria-busy={!status && !error}>
              <div className="card-heading">
                <div className="status-heading">
                  <span className={`status-dot ${status?.virtualHidAvailable ? "is-ready" : "is-pending"}`} aria-hidden="true" />
                  <div>
                    <Text size="sm" tone="muted">가상 인증기</Text>
                    <Heading level="2" size="xl">{statusTitle}</Heading>
                  </div>
                </div>
                <Badge variant="weak" size="small" color={status?.virtualHidAvailable ? "green" : "yellow"}>
                  {statusBadge}
                </Badge>
              </div>
              <Text tone="subtle">{error ?? status?.statusMessage ?? "시스템 상태를 확인하고 있습니다…"}</Text>
            </div>
            {status?.providerKeyCleanupPending && (
              <p className="callout is-warning" role="alert">
                서명 키 정리가 완료되지 않아 인증기 작업이 차단되어 있습니다. 다음 인증기 요청에서 정리를 다시 시도하며, 완료되면 이 안내가 사라집니다. 자격 증명 초기화 상태와는 별개입니다.
              </p>
            )}
            {status?.authenticatorResetPending && (
              <p className="callout is-warning" role="alert">
                인증기 초기화가 완료되지 않았습니다. 정리가 끝날 때까지 인증 요청은 차단됩니다. 다음 인증 요청에서 자동으로 정리를 재개하며, 계속 실패하면 인증기를 중지하고 초기화를 다시 시도하세요.
              </p>
            )}
            {runtimeError && <p className="callout is-danger" role="alert">{runtimeError}</p>}
            {showRuntimeActions && (
              <div className="actions">
                {canStart && (
                  <Button variant="primary" loading={runtimeAction} disabled={runtimeAction} onClick={() => void startAuthenticator()}>
                    인증기 시작
                  </Button>
                )}
                {status?.authenticatorRunning && (
                  <Button variant="danger" disabled={runtimeAction} onClick={() => void stopAuthenticator()}>
                    인증기 중지
                  </Button>
                )}
                {status?.credentialStoreAvailable && (
                  <Button
                    variant="secondary"
                    disabled={status.authenticatorRunning}
                    onClick={() => setShowCredentials((visible) => !visible)}
                  >
                    {showCredentials ? "자격 증명 숨기기" : "등록된 자격 증명 관리"}
                  </Button>
                )}
              </div>
            )}

            <dl className="details">
              {details.map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
            <p
              className="footnote"
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
        </Card>

        {isTauri() && status?.credentialStoreAvailable && !status.authenticatorRunning &&
          (status.clientPinStatus === "Configured" || status.clientPinStatus === "Not configured") && (
          <Card elevation="low" padding="large">
            <form className="stack" onSubmit={(event) => void submitClientPin(event)}>
              <Heading level="2" size="lg">
                {status.clientPinStatus === "Configured" ? "인증기 PIN 변경" : "인증기 PIN 설정"}
              </Heading>
              {status.clientPinStatus === "Configured" && (
                <TextField ref={currentPinRef} label="현재 PIN" type="password" autoComplete="off" disabled={pinAction} />
              )}
              <TextField ref={newPinRef} label="새 PIN" type="password" autoComplete="off" disabled={pinAction} />
              <TextField
                ref={confirmPinRef}
                label="새 PIN 확인"
                type="password"
                autoComplete="off"
                disabled={pinAction}
                helperText="최소 4개의 Unicode 코드 포인트, UTF-8 기준 최대 63바이트입니다. 보호된 저장소에 PIN 검증값만 저장됩니다."
              />
              <div className="actions">
                <Button variant="primary" loading={pinAction} disabled={pinAction} onClick={() => void submitClientPin()}>
                  PIN 저장
                </Button>
              </div>
              {pinError && <p role="alert" className="callout is-danger">{pinError}</p>}
              {pinMessage && <p role="status" className="callout is-success">{pinMessage}</p>}
            </form>
          </Card>
        )}

        {showCredentials && status?.credentialStoreAvailable && (
          <Card elevation="low" padding="large">
            <section className="stack" aria-label="등록된 자격 증명">
              <div className="card-heading">
                <div>
                  <Text size="sm" weight="semibold" tone="primary">Credential management</Text>
                  <Heading level="2" size="lg">등록된 자격 증명</Heading>
                </div>
                <div className="actions">
                  <Button variant="tertiary" size="small" disabled={status.authenticatorRunning || resetAction} onClick={() => void loadCredentials()}>
                    새로고침
                  </Button>
                  <Button variant="danger" size="small" loading={resetAction} disabled={status.authenticatorRunning || resetAction} onClick={() => void resetCredentials()}>
                    {status.authenticatorResetPending ? "초기화 재시도" : "모든 자격 증명 초기화"}
                  </Button>
                </div>
              </div>
              {credentialError && <p className="callout is-danger" role="alert">{credentialError}</p>}
              {status.authenticatorResetPending ? (
                <p className="empty">초기화 정리가 완료될 때까지 자격 증명을 사용할 수 없습니다.</p>
              ) : credentials.length === 0 ? (
                <p className="empty">등록된 자격 증명이 없습니다.</p>
              ) : (
                <div className="list">
                  {credentials.map((credential) => (
                    <ListRow
                      key={credential.creationOrder}
                      title={credential.relyingPartyId ?? "알 수 없는 사이트 (기존 자격 증명)"}
                      description={[
                        credential.userDisplayName ?? credential.userName,
                        credential.keyProtection,
                        credential.exportable ? "추출 가능" : "추출 불가",
                        credential.discoverable ? "discoverable" : "allow-list 전용",
                      ].filter(Boolean).join(" · ")}
                      trailing={
                        <Button variant="danger" size="small" disabled={status.authenticatorRunning} onClick={() => void deleteCredential(credential)}>
                          삭제
                        </Button>
                      }
                    />
                  ))}
                </div>
              )}
            </section>
          </Card>
        )}

        <div className="callout is-info" role="note">
          {status?.authenticatorRunning
            ? "인증기가 실행 중입니다. 자격 증명 생성과 인증은 각각 사용자 승인이 필요합니다."
            : status?.hostPlatform === "Windows"
              ? "Windows에서는 검증된 UDE 드라이버와 TPM 보호 키 저장소가 준비된 경우에만 인증기를 시작할 수 있습니다."
              : status?.hostPlatform === "macOS"
                ? "macOS 인증기를 시작하려면 할당된 제품 ID와 Apple의 서명된 HID entitlement가 필요합니다."
                : "Linux에서 인증기를 시작하려면 세션별 소프트웨어 키 사용 동의가 필요합니다."}
        </div>

        {isTauri() && (
          <Card elevation="flat" padding="large">
            <section className="stack" aria-label="Redacted diagnostic events">
              <div className="card-heading">
                <div>
                  <Text size="sm" weight="semibold" tone="primary">Local diagnostics</Text>
                  <Heading level="2" size="lg">Redacted events</Heading>
                </div>
                <div className="actions">
                  <Button
                    variant="secondary"
                    size="small"
                    onClick={() => {
                      setShowDiagnosticLog(true);
                      void loadDiagnosticLog();
                    }}
                  >
                    {showDiagnosticLog ? "Refresh" : "View events"}
                  </Button>
                  {showDiagnosticLog && (
                    <Button variant="tertiary" size="small" onClick={() => setShowDiagnosticLog(false)}>
                      Hide
                    </Button>
                  )}
                </div>
              </div>
              {showDiagnosticLog && (
                <>
                  <Text size="sm" tone="muted">Fixed event codes and coarse outcomes only. Entries stay on this device.</Text>
                  {diagnosticLogLoading ? (
                    <p className="footnote" role="status">Loading diagnostics…</p>
                  ) : diagnosticLogError ? (
                    <p className="footnote" role="status">{diagnosticLogError}</p>
                  ) : (
                    <pre className="diagnostic-log" aria-live="polite">
                      {diagnosticLog || "No diagnostic events have been recorded."}
                    </pre>
                  )}
                </>
              )}
            </section>
          </Card>
        )}
      </main>

      <footer className="app-footer">
        <span>{status?.productName ?? "Ghost FIDO Key"} {status?.productVersion ?? "0.1.0"}</span>
        <span>로컬 상태만 표시합니다</span>
      </footer>
    </div>
  );
}

export default App;
