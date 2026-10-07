# 방어적 평가

<p align="right">
  <a href="./EVALUATION.md">English</a> | <strong>한국어</strong>
</p>

이 평가는 체크인된 적대적 픽스처로 강제되는 동작을 기록합니다. 재현하려면 `npm run test:research`를 실행하세요. 테스트는 로컬 정적 검사만 수행하며 설정된 서버를 실행하거나 연결하지 않습니다.

## MCP 정책 사례

사례는 `examples/adversarial/policy.json`의 작은 오버레이와 함께 기본 제공 `strict` 정책을 사용합니다.

| 사례 | 필수 증거 | 예상 결정 | 이유 |
| --- | --- | --- | --- |
| `trusted-pinned-package` | 고정된 패키지, 명시적으로 신뢰된 패키지 이름 | `ALLOW` | 설정된 버전이 고정되어 있고 정책에 명시적인 패키지 신뢰 규칙이 있음 |
| `floating-version` | `install-on-run`, `unbounded-version` | `BLOCK` | 유동 패키지 버전은 검토 없이 변경될 수 있음 |
| `shell-launcher` | `shell-execution`, `filesystem-path` | `BLOCK` | 엄격한 정책이 셸 실행을 차단함 |
| `credential-bearing-url` | `embedded-credentials`, `network-endpoint`, `url-query-parameters` | `BLOCK` | 호스트가 허용 목록에 있어도 URL에 포함된 자격 증명은 차단 신호임 |
| `insecure-remote` | `insecure-transport`, `network-endpoint` | `BLOCK` | 호스트가 허용 목록에 있어도 평문 전송은 차단 신호임 |
| `sensitive-local-env` | `filesystem-path`, `secret-env` | `ASK` | 비밀 정보로 보이는 환경 변수 이름을 사용하는 로컬 확장에는 검토가 필요함 |
| `unknown-remote` | `network-endpoint` | `BLOCK` | 원격 호스트에 명시적인 허용 목록 또는 출처 증거가 없음 |

예상 합계: `ALLOW` 1개, `ASK` 1개, `BLOCK` 5개.

## 드리프트 사례

드리프트 픽스처는 신뢰되는 고정 패키지에서 시작한 뒤 `API_TOKEN` 환경 키를 추가합니다. 회귀 테스트는 다음 변경을 모두 요구합니다.

- `secret-env`에 대한 `signals-added`
- `ALLOW`에서 `ASK`로의 `decision-changed`
- `fingerprint-changed`

자리표시자 값 자체는 검사 결과나 스냅샷 어디에도 나타나면 안 됩니다.

## 이 평가가 측정하지 않는 것

이 벤치마크는 의도적으로 범위가 좁습니다. 런타임 동작, 샌드박스 탈출, 임의의 악성 코드, 모든 형태의 프롬프트 인젝션, 게시자 신원 소유권 또는 전이 의존성의 취약점을 측정하지 않습니다. 특히 이미 실행 중인 MCP 서버가 동적으로 반환하는 도구 설명은 현재 정적 설정 경계 밖에 있습니다.

이 작은 픽스처 집합은 회귀 기준선이지 탐지 정확도에 대한 통계적 주장이 아닙니다. 거짓 양성과 거짓 음성 비율을 측정하려면 민감 정보를 제거한 실제 설정으로 구성되고 독립적으로 검토된 더 큰 코퍼스가 필요합니다.
