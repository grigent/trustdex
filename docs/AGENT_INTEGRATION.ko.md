# 에이전트 연동

<p align="right">
  <a href="./AGENT_INTEGRATION.md">English</a> | <strong>한국어</strong>
</p>

AI 에이전트는 점점 더 스스로 도구를 설치하고 호출합니다. TrustDex는 도구가 노출되기 전에 에이전트나 그 하네스가 실행하는 검사가 될 수 있습니다. 다만 다음 두 가지가 지켜질 때만 그렇습니다.

1. 에이전트가 TrustDex의 답을 실패 시 허용(fail open)될 수 없는 방식으로 읽어야 합니다.
2. 에이전트가 그 답을 만드는 정책, 신뢰 저장소, 승인 기록을 바꿀 수 없어야 합니다.

이 문서는 (1)을 위한 기계 판독 계약과 (2)를 위한 운영 규칙을 정의합니다.

## 판정 계약

모든 검사 명령(`inspect`, `inspect-claude`, `inspect-skill`, `inspect-plugin`, `inspect-codex`, `inspect-claude-settings[-stack]`, `inspect-codex-settings[-stack]`, `inspect-ide-extensions`)은 `--decisions`를 받습니다(TrustDex 0.12.0 이상).

```bash
npx trustdex@<exact-version> inspect ./.mcp.json --pack strict --policy ./trustdex.policy.json --decisions
```

이 명령은 [`schemas/trustdex-decisions-v1.schema.json`](../schemas/trustdex-decisions-v1.schema.json)에 정의된 JSON 객체 하나를 출력합니다.

```json
{
  "schemaVersion": 1,
  "kind": "trustdex-decisions",
  "command": "inspect",
  "trustdexVersion": "<version>",
  "policyDigest": "<유효 정책의 sha256>",
  "decision": "ask",
  "exitCode": 1,
  "counts": { "allow": 1, "ask": 1, "block": 0 },
  "items": [
    {
      "name": "filesystem",
      "kind": "mcp",
      "action": "allow",
      "signals": [],
      "reasons": ["trusted package: @modelcontextprotocol/server-filesystem"],
      "fingerprint": "<sha256>"
    }
  ],
  "digest": "<보고서 본문의 sha256>"
}
```

- `decision`은 항목 중 가장 엄격한 판정입니다. `exitCode`는 allow `0`, ask `1`, block `2`이며 프로세스 종료 코드와 같습니다.
- 항목에는 이름, 판정, 신호 이름, 이유, 지문이 들어갑니다. 이유에는 패키지, 호스트, 저장소, 확장 ID, 신뢰 저장소 게시자 이름이 나올 수 있습니다. 자격 증명, 환경 변수·헤더 값, 출처 증거 같은 값은 절대 들어가지 않습니다. 항목 메타데이터와 환경 변수 이름도 들어가지 않습니다.
- 검사가 실패해도(파일 없음, 잘못된 입력, 잘못된 정책) `"decision": "block"`, `"exitCode": 2`, 빈 `items`, 고정된 `error` 문자열을 담은 보고서를 출력합니다. 자세한 내용은 stderr로 갑니다. 필드, 서버, 신호, 정책 항목의 이름은 나올 수 있지만 자격 증명, 헤더, 환경 변수 같은 설정 값은 인용하지 않습니다.
- 빈 인벤토리(예: `{}`, 빈 TOML 파일, 빈 확장 디렉터리)는 `"ask"`와 종료 코드 `1`로 보고합니다. 아무것도 평가하지 않았다는 뜻이며, 대개 잘못된 파일을 검사했다는 신호입니다.
- `--decisions`는 검사 명령만 받습니다. 다른 명령에 `--decisions`를 주면 BLOCK 보고서와 종료 코드 `2`로 실패하므로, 이 플래그가 조용히 무시되는 일은 없습니다.
- `digest`는 같은 결과와 정책에 대해 항상 같으므로, 하네스는 어떤 판정에 따라 행동했는지 정확히 기록할 수 있습니다.

### 안전하게 읽는 법

다음 조건이 **모두** 참일 때만 도구를 노출하세요.

- 프로세스 종료 코드가 `0`
- stdout이 `schemaVersion` `1`, `kind` `"trustdex-decisions"`인 JSON으로 파싱됨
- `decision`이 `"allow"`

시간 초과, 빈 출력, 알 수 없는 `schemaVersion`, `"ask"`를 포함한 그 밖의 모든 경우는 BLOCK으로 취급해야 합니다. `"ask"`는 사람이 검토해야 한다는 뜻입니다. 에이전트는 이를 허락으로 여기면 안 되고, 더 나은 답을 얻으려고 다른 팩, 정책, 플래그로 다시 실행해서도 안 됩니다.

최소한의 하네스 검사:

```bash
report="$(npx trustdex@<exact-version> inspect ./.mcp.json --pack strict --policy ./policy.json --decisions)"
status=$?
node -e '
  const r = JSON.parse(process.argv[1]);
  const ok = r.schemaVersion === 1 && r.kind === "trustdex-decisions" && r.decision === "allow";
  process.exit(ok ? 0 : 1);
' "$report" && [ "$status" -eq 0 ] || { echo "TrustDex did not allow these tools"; exit 1; }
```

## 게이트를 에이전트 손이 닿지 않게 두기

TrustDex는 에이전트가 건드릴 수 없는 입력만큼만 신뢰할 수 있습니다. 에이전트가 명령을 실행할 수 있는 곳에서는 다음 규칙을 지키세요.

| 규칙 | 이유 |
|---|---|
| 정책 파일, 신뢰 저장소, 검토 디렉터리는 사람이 소유합니다. 에이전트에게는 읽기 전용으로 두세요(파일 권한, 별도 체크아웃, 또는 해당 경로에 대한 에이전트의 거부 규칙). | 정책을 수정할 수 있는 에이전트는 스스로를 허용할 수 있습니다. |
| 검토 서명용 개인 키는 에이전트가 쓰는 컴퓨터 밖에 두세요. | 키가 없으면 에이전트는 `recheck`가 받아들이는 승인을 만들 수 없습니다. |
| 에이전트에게는 `inspect*`, `gate*`, `recheck*`만 허용하세요. `approve*`, `sign`, `keygen`, `trust-source`는 절대 실행하게 하지 마세요. | 이 명령들은 신뢰를 만들어 내는 사람의 결정입니다. |
| 사람이 서명한 검토를 기준으로 `recheck`, `recheck-claude`, `recheck-ide-extensions`를 쓰세요. | 서명된 검토는 정책과 모든 지문을 고정하므로, 어떤 변화든 `NEEDS_REVIEW`가 됩니다. |
| `--pack`을 명시하고 에이전트가 `development`를 고르지 못하게 하세요. | `development`는 여러 BLOCK 판정을 ASK로 완화합니다. |
| 실행하는 TrustDex 버전을 고정하고(`npx trustdex@<정확한 버전>`) [릴리스](RELEASING.ko.md)에 설명된 대로 릴리스를 검증하세요. | 게이트 자체도 공급망의 일부입니다. |
| `inspect-claude-settings` 또는 `inspect-codex-settings`로 에이전트 자신의 권한 설정을 검사하세요. | 광범위한 자동 셸·파일 권한이 있으면 에이전트가 위 규칙을 모두 우회할 수 있습니다. |

정책 파일은 엄격하게 검증합니다. 알 수 없는 필드, `signalActions`의 알 수 없는 신호 이름, 정확한 버전이 없는 IDE 확장 항목, 지원하지 않는 버전, 잘못된 판정 값은 무시하지 않고 거부하므로, 오타나 조작된 필드가 판정을 조용히 바꿀 수 없습니다. 허용되는 형식은 [`schemas/trustdex-policy-v1.schema.json`](../schemas/trustdex-policy-v1.schema.json)에, 서명된 스냅샷 형식은 [`schemas/trust-snapshot-v3.schema.json`](../schemas/trust-snapshot-v3.schema.json)에 공개되어 있습니다.

## 호환성 규칙

- v1 판정 계약에는 필드를 무시하는 소비자가 여전히 안전할 때만 필드를 추가합니다. 기존 필드의 의미를 바꾸거나 `decision`, `action`에 값을 추가하는 변경은 새 `schemaVersion`으로 배포합니다.
- 소비자는 모르는 `schemaVersion`을 거부해야 합니다.
- 사람이 읽는 출력과 `--json` 출력은 이 계약에 포함되지 않으며 바뀔 수 있습니다.

## 한계

- ALLOW 판정은 정적 증거에 대한 정책 결과입니다. 도구가 안전하다는 것을 증명하지 않으며 샌드박스도 아닙니다.
- 이미 제한 없는 셸·파일 접근 권한을 가진 에이전트가 하네스를 우회하는 것은 TrustDex가 막을 수 없습니다. 실제 강제는 에이전트 런타임의 권한 시스템과 OS 수준 격리로 하세요.
