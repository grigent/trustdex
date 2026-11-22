# 신뢰 저장소와 출처

<p align="right">
  <a href="./TRUST_STORE.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 패키지 이름, GitHub 스타 수 또는 브랜딩으로 게시자가 "공식"인지 추측하지 않습니다.

사용자 또는 조직이 로컬 신뢰 저장소에 명시적인 주장을 배치한 경우에만 소스에 `verified` 출처 주장을 부여할 수 있습니다.

## 형식

```json
{
  "version": 1,
  "claims": [
    {
      "type": "package",
      "subject": "example-mcp-server",
      "publisher": "Example Publisher",
      "status": "verified",
      "evidence": {
        "kind": "manual-review",
        "reference": "https://example.invalid/security-review",
        "checkedAt": "2026-09-19T00:00:00Z"
      }
    }
  ]
}
```

지원되는 주장 유형:

- `package` - npm/Python 형식의 패키지 주체
- `remote` - 원격 MCP 호스트 이름
- `repository` - 향후 저장소 어댑터용 저장소 신원

`verified`라는 단어는 **신뢰 저장소 유지관리자가 기록한 증거에 따라 검증됨**을 의미합니다. OpenAI, TrustDex, GitHub, npm 또는 다른 플랫폼이 확장을 인증했다는 의미가 아닙니다.

## 사용하기

```bash
node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --pack official-first \
  --trust-store ./examples/trust-store.example.json
```

알 수 없는 서드파티 소스는 `official-first`에서 계속 차단됩니다. 검증된 출처 주장은 초기 신뢰를 설정할 수 있지만 셸 실행과 같은 차단 기능 신호는 여전히 해당 신뢰보다 우선할 수 있습니다.

## 권장 사례

- 팀 정책인 신뢰 저장소는 소스 관리에 보관
- 각 주장을 지속 가능한 증거에 연결
- 가능한 경우 패키지 버전 또는 소스 커밋 고정
- 소유권이나 기능이 변경되면 주장을 재검토
- 증거 필드에 자격 증명, 토큰, 비공개 URL 또는 비밀을 기록하지 않음

## npm 빌드 출처

`provenance npm`과 `trust-source npm`은 최신 버전에 대해 npm이 알려주는 SLSA provenance도 읽습니다. 그 안의 소스 저장소를, 패키지가 지금 선언한 저장소와 직전 버전이 선언했던 저장소와 비교합니다.

| 결과 | 의미 | `trust-source` |
|---|---|---|
| `matched` | 선언한 GitHub 저장소에서 빌드됨 | 주장에 `buildProvenance`(소스 저장소, 워크플로 경로)를 기록 |
| `absent` | 이 패키지는 provenance를 게시한 적이 없음 | 이 항목 없이 주장을 기록 |
| `dropped` | 이전 버전에는 provenance가 있었는데 최신 버전에는 없음 | 거부 |
| `mismatch` | 패키지가 선언한(또는 이전에 선언했던) 저장소와 다른 저장소에서 빌드됨. 공격자 포크에서 빌드한 릴리스가 이런 모습 | 거부 |
| `unverifiable` | 증명을 받아오거나 해석하지 못했거나, 증명 대상이 해당 버전의 sha512와 맞지 않음 | 거부 |

증명은 이 명시적 명령을 실행할 때만 `registry.npmjs.org`에서 정확한 이름과 버전으로 받아옵니다. `check-install`과 `claude-hook`은 이 요청을 하지 않습니다. 증명이 정확한 버전과 sha512 다이제스트를 가리키는지 확인하고, Sigstore 번들을 Node 내장 crypto와 패키지에 고정된 신뢰 루트로 오프라인 검증합니다(추가 요청과 의존성 없음). 다음이 모두 성립할 때만 `signatureVerified: true`로 일치를 기록합니다. DSSE 서명이 서명 인증서로 검증되고, 그 인증서가 고정된 Fulcio 루트로 이어지며 기록 시각에 유효하고, GitHub Actions용으로 발급되어 같은 소스 저장소를 가리키고, Rekor 로그 항목이 바로 이 봉투에 대한 것이며 고정된 로그 키의 서명된 타임스탬프가 유효해야 합니다. 그 외에는 `unverifiable`이며 `trust-source`가 거부합니다.

확인하지 않는 것: 인증서 투명성 SCT, 머클 포함 증명, RFC 3161 타임스탬프, 신뢰 루트 교체(루트가 고정되어 있어 더 새로운 Sigstore 키로 서명된 릴리스는 TrustDex를 업데이트하기 전까지 `unverifiable`로 표시됩니다). 서명이 검증되었다는 것은 어느 저장소의 워크플로가 패키지를 빌드했는지를 보여줄 뿐, 그 저장소나 워크플로가 안전하다는 증명은 아닙니다.

## 무결성 기반 패키지 증거

`trust-source npm` 및 `trust-source mcp`의 선택적 `--artifact` 플래그는 아티팩트 증거를 기록하기 전에 사용자가 제공한 파일을 검증합니다.

- npm 관찰에는 SHA-256, SHA-384 또는 SHA-512를 사용하는 SRI 값이 필요합니다.
- MCP Registry 관찰에는 SHA-256 다이제스트가 있는 단일 패키지가 필요합니다.
- 파일은 로컬에서 읽으며 실행하거나 업로드하지 않습니다.
- 신뢰 저장소 주장은 레지스트리 식별자, 버전, 예상 무결성 메타데이터, 계산된 다이제스트 및 검증 시간을 기록합니다.
- 설정된 패키지 버전은 검증된 아티팩트 버전과 일치해야 합니다.

증거 형식 예시:

```json
{
  "kind": "npm-registry",
  "reference": "https://www.npmjs.com/package/example-mcp-server",
  "checkedAt": "2026-09-19T00:00:00Z",
  "artifact": {
    "registryType": "npm",
    "identifier": "example-mcp-server",
    "version": "1.2.3",
    "integrity": "sha512-..."
  },
  "artifactVerification": {
    "verified": true,
    "algorithm": "sha512",
    "digest": "...",
    "encoding": "base64",
    "version": "1.2.3",
    "identifier": "example-mcp-server",
    "verifiedAt": "2026-09-19T00:00:01Z"
  }
}
```

아티팩트 무결성은 제공된 바이트가 해당 시점에 관찰된 레지스트리 메타데이터와 일치한다는 것만 증명합니다. 바이트가 안전하다는 것, 레지스트리 계정이 침해되지 않았다는 것 또는 게시자 이름이 합법적이라는 것은 증명하지 않습니다.
