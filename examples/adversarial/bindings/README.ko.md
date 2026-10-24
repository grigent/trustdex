# 도구 출처와 권한 결합 픽스처

이 비활성 픽스처는 MCP 서버의 정책/출처 결과와 해당 서버에 부여된 자동 도구
권한을 값 없이 연결하는 TrustDex 동작을 검증합니다. 예약된 `.invalid` 도메인과
자리표시자 마커만 사용하며, 검사는 서버에 연결하거나 서버를 실행하지 않습니다.

```bash
node ../../../bin/trustdex.mjs snapshot-claude-bindings ./claude.mcp.json \
  --settings ./claude.settings.json \
  --trust-store ./trust-store.json \
  --out ./claude.bindings.json

node ../../../bin/trustdex.mjs snapshot-codex-bindings ./codex.toml \
  --trust-store ./trust-store.json \
  --out ./codex.bindings.json
```

검토된 Claude 서버의 범위 제한 승인은 `ALLOW` 결과와 결합됩니다. 출처를 알 수
없는 서버의 와일드카드 승인은 `BLOCK` 결과와 결합됩니다. 일치하지 않는 Claude
권한 규칙은 개수만 기록하고 값은 보관하지 않습니다. Codex의 검토된 서버도
`default_tools_approval_mode = "approve"`가 모든 도구를 승인하므로 재검토가 필요합니다.

생성된 보고서는 엔드포인트 경로, 권한 지정자, 도구 이름 및 마커 값을 의도적으로
제외합니다. `expected.json`은 안정적인 구조적 결과만 기록합니다.
