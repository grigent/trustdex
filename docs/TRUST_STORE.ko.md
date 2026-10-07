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
