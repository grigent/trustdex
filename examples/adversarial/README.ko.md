# 비활성 적대적 픽스처

<p align="right">
  <a href="./README.md">English</a> | <strong>한국어</strong>
</p>

이 파일들은 TrustDex 정책 경계의 재현 가능한 방어적 테스트를 제공합니다.

- `mcp-config.json`에는 정적인 MCP 설정 사례 7개가 포함되어 있습니다.
- `policy.json`은 소스 허용 목록과 독립적으로 차단 신호를 테스트할 수 있도록 픽스처 패키지 1개와 픽스처 호스트 2개를 명시적으로 신뢰합니다.
- `expected.json`은 필수 결정과 최소 신호를 기록합니다.
- `drift-before.json`과 `drift-after.json`은 검토된 패키지에 비밀 정보를 포함하는 환경 키가 추가되는 상황을 모델링합니다.

모든 패키지 이름은 가상이며, 모든 원격 엔드포인트는 예약된 `.invalid` 최상위 도메인을 사용하고, 자격 증명으로 보이는 모든 값은 자리표시자입니다. 이를 실제 값으로 바꾸지 마세요. TrustDex는 이 파일을 읽지만 나열된 명령을 실행하거나 나열된 엔드포인트에 연결하지 않습니다.

강제 평가 실행:

```bash
npm run test:research
```

사람이 읽을 수 있는 결정을 직접 검사:

```bash
node ./bin/trustdex.mjs inspect \
  ./examples/adversarial/mcp-config.json \
  --pack strict \
  --policy ./examples/adversarial/policy.json
```

차단 사례가 있으므로 두 번째 명령은 종료 코드 `2`를 반환합니다. 예상 결과와 제한 사항은 [평가 기록](../../docs/EVALUATION.ko.md)을 참고하세요.
