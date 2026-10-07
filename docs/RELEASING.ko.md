# TrustDex 릴리스

<p align="right">
  <a href="./RELEASING.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 두 개의 작은 GitHub Actions 워크플로를 사용합니다.

- `release.yml`은 테스트 통과 후 GitHub 태그와 릴리스를 생성합니다.
- `publish.yml`은 바로 그 태그를 npm에 게시합니다.

이 분리는 GitHub 릴리스 생성과 레지스트리 자격 증명을 분리합니다.

## 최초 게시

일회성 토큰 기반 최초 게시는 완료되었습니다. 일반 릴리스에서 반복하지 마세요.

단기 `NPM_TOKEN`은 신뢰할 수 있는 게시를 설정하고 검증할 때까지만 유지할 수 있습니다. 최초 OIDC 게시에 성공한 즉시 npm 토큰과 GitHub 저장소 비밀을 모두 삭제하세요.

npm 자격 증명을 이슈, 풀 리퀘스트, 소스 파일, 로그 또는 채팅에 붙여 넣지 마세요.

## npm 신뢰할 수 있는 게시

패키지가 만들어진 뒤 다음 값으로 npm 신뢰할 수 있는 게시를 설정합니다.

- GitHub 사용자/조직: `grigent`
- 저장소: `trustdex`
- 워크플로 파일 이름: `publish.yml`
- 허용 작업: 직접 `npm publish`

워크플로는 `contents: read`와 `id-token: write`만 부여합니다. 그러면 npm은 장기 쓰기 토큰 대신 OIDC로 GitHub 호스팅 작업을 인증할 수 있습니다.

신뢰할 수 있는 게시가 작동하면 `NPM_TOKEN` 저장소 비밀을 제거하고 npm에서 최초 게시 토큰을 폐기합니다. npm이 OIDC 인증을 선택할 수 있도록 워크플로는 의도적으로 표준 `npm publish` 명령을 계속 사용합니다.

두 릴리스 워크플로는 `npm pkg fix`를 실행하고 패킹 또는 게시 전에 깨끗한 `package.json` 차이를 요구합니다. 이렇게 하면 npm이 CLI 진입점 같은 중요한 메타데이터를 조용히 정규화해 없애는 것을 방지합니다.

## 출처 및 릴리스 증거

저장소와 패키지가 공개이므로 GitHub 호스팅 게시는 npm 출처를 생성할 수 있습니다. 워크플로는 `--provenance`도 명시적으로 전달합니다.

출처는 게시된 아티팩트를 해당 소스/빌드 환경과 연결합니다. 패키지에 악성 동작이 없다는 것을 증명하지는 않습니다.

GitHub 릴리스 워크플로는 다음도 생성하고 업로드합니다.

- 릴리스 커밋에서 빌드한 npm 패키지 tarball
- CycloneDX JSON SBOM
- tarball과 SBOM을 포함하는 `SHA256SUMS` 파일
- tarball용 GitHub 빌드 출처 증명
- SBOM을 tarball에 연결하는 GitHub SBOM 증명

릴리스를 다운로드한 뒤 검사 또는 설치하기 전에 체크섬과 GitHub 증명을 검증하세요.

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify trustdex-<version>.tgz --repo grigent/trustdex
```

npm 출처 진술과 GitHub 증명은 서로 다른 게시 경로를 다룹니다. 어느 쪽도 악성 코드 분석이 아니며 릴리스 콘텐츠와 문서화된 신뢰 경계를 검토하는 일을 대신하지 않습니다.

## 버전 체크리스트

각 릴리스 전에:

1. `package.json` 버전 업데이트
2. 해당 변경 기록 섹션을 `Unreleased` 밖으로 이동
3. CI가 통과하는지 확인
4. 정확히 `v<package version>`으로 릴리스 워크플로 실행
5. 바로 그 릴리스 태그에 대해 게시 워크플로 실행

게시 워크플로는 최신 브랜치 HEAD가 아니라 태그 SHA를 체크아웃하므로 npm 아티팩트에 이후 커밋이 조용히 포함될 수 없습니다.
