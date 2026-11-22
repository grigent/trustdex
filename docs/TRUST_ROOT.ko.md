# 고정된 Sigstore 신뢰 루트 갱신

<p align="right">
  <a href="./TRUST_ROOT.md">English</a> | <strong>한국어</strong>
</p>

`provenance npm`과 `trust-source npm`은 npm 빌드 provenance를
[`src/sigstore-trust-root.mjs`](../src/sigstore-trust-root.mjs)에 고정된 키로 검증합니다.
Sigstore 공개 인스턴스의 Fulcio 인증서 체인, Rekor v1 로그 키, 인증서 투명성 로그 키가
들어 있습니다. TrustDex는 실행 중에 이 값을 내려받지 않습니다. 이 문서는 그 값을 바꾸는
유지보수 절차입니다.

## Sigstore가 키를 교체하면

위험해지지는 않습니다. 고정되지 않은 키로 서명된 릴리스는 `unverifiable`로 표시되고,
새 키를 고정한 TrustDex 릴리스가 나오기 전까지 `trust-source`가 거부합니다. 오래된
루트의 대가는 거부되는 릴리스이지, 받아들여지는 위조가 아닙니다. 설치 검사
(`check-install`, `claude-hook`)는 신뢰 루트를 쓰지 않으므로 영향이 없습니다.

## 갱신 시점

- Sigstore가 교체를 공지하거나,
  [sigstore/root-signing](https://github.com/sigstore/root-signing)의
  `targets/trusted_root.json`이 바뀌었을 때. 고정값을 만든 파일의 SHA-256은
  `src/sigstore-trust-root.mjs` 머리말에 있습니다.
- 최신 Sigstore 클라이언트로는 검증되는 릴리스가 여기서 `unverifiable`로 나오기 시작할 때.

## 절차

1. 새 `trusted_root.json`은 Sigstore의 TUF 메타데이터를 검증하는 클라이언트를 통해
   얻습니다(예: 최신 `@sigstore/tuf`나 `cosign initialize`가 기록하는 사본). 단순
   다운로드로 받지 않습니다. 그 SHA-256을 서명된 릴리스 시점의 sigstore/root-signing
   `targets/trusted_root.json`과 비교합니다. 이슈, 채팅 메시지 등 제3자가 건넨 파일은
   쓰지 않습니다.
2. `test/fixtures/sigstore-trusted-root.json`을 그 파일로 그대로 교체합니다.
3. `src/sigstore-trust-root.mjs`를 갱신합니다. 머리말의 SHA-256과 클라이언트 버전,
   그리고 상수 세 개입니다. 파일에 있는 값을 그대로 씁니다.
4. `npm test`를 실행합니다. `test/sigstore-trust-root.test.mjs`는 머리말 해시가 픽스처와
   일치하고 상수가 픽스처에서 나오는 값과 정확히 같을 때까지 실패합니다. 따라서 업스트림
   파일에 근거가 없으면 키를 손으로 추가·변경·삭제할 수 없습니다.
5. 교체 전에 게시된 패키지와 교체 후에 게시된 패키지를 포함해 몇 개를
   `provenance npm`으로 실제 확인합니다.
6. 이 변경만 담은 풀 리퀘스트를 엽니다. 평소와 같은 필수 검사와 리뷰가 필요하며, 누구도
   자신의 신뢰 루트 변경을 검사와 리뷰 없이 병합하지 않습니다.

## 규칙

- 업스트림이 여전히 나열하는 항목은 삭제하지 않습니다. 은퇴한 키는 `validFor` 종료일을
  유지합니다. 그래야 유효하던 기간에 서명된 릴리스는 계속 검증되고, 그 이후의 것은
  보증하지 못합니다.
- `validFor` 기간을 넓히거나 업스트림 파일에 없는 키를 추가하지 않습니다.
- ECDSA P-256 Rekor v1 로그만 고정합니다. 업스트림 파일에는 Rekor v2 로그(Ed25519)도
  있지만, 그 로그에만 기록된 번들은 검증기가 해당 로그를 지원하기 전까지
  `unverifiable`이며, 키만 고정해서는 달라지지 않습니다.
- RFC 3161 타임스탬프를 확인하지 않으므로 타임스탬프 기관은 고정하지 않습니다.
