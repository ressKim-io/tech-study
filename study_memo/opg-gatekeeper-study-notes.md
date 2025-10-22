# Kubernetes OPA Gatekeeper 실무 가이드

## 📋 목차
1. [핵심 개념](#핵심-개념)
2. [설치 및 초기 설정](#설치-및-초기-설정)
3. [필수 보안 정책](#필수-보안-정책)
4. [실무 트러블슈팅](#실무-트러블슈팅)
5. [모니터링 및 감사](#모니터링-및-감사)
6. [운영 베스트 프랙티스](#운영-베스트-프랙티스)

---

## 🎯 핵심 개념

### OPA Gatekeeper 구조
```
ConstraintTemplate (정책 템플릿)
    ↓
Constraint (실제 정책 적용)
    ↓
Admission Webhook (실시간 검증)
```

### 주요 컴포넌트
- **ConstraintTemplate**: Rego 언어로 작성된 정책 로직
- **Constraint**: 특정 네임스페이스/리소스에 정책 적용
- **Admission Controller**: 리소스 생성/수정 시 실시간 검증

---

## 🚀 설치 및 초기 설정

### Gatekeeper 설치
```bash
# 최신 릴리즈 설치
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# 설치 확인
kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper
```

### 네임스페이스 준비
```bash
# 테스트용 네임스페이스 생성
kubectl create namespace secure-app
kubectl label namespace secure-app admission.gatekeeper.sh/ignore!=true
```

---

## 🔒 필수 보안 정책

### 1. 권한 상승 금지 정책

**ConstraintTemplate**:
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8scontainernoprivilegeescalation
  annotations:
    description: "컨테이너의 권한 상승을 금지합니다"
spec:
  crd:
    spec:
      names:
        kind: K8sContainerNoPrivilegeEscalation
      validation:
        openAPIV3Schema:
          type: object
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8scontainernoprivilegeescalation

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          allows_privilege_escalation(container)
          msg := sprintf("컨테이너 '%v'는 allowPrivilegeEscalation을 false로 설정해야 합니다", [container.name])
        }

        allows_privilege_escalation(container) {
          not container.securityContext
        }

        allows_privilege_escalation(container) {
          container.securityContext
          not has_key(container.securityContext, "allowPrivilegeEscalation")
        }

        allows_privilege_escalation(container) {
          container.securityContext.allowPrivilegeEscalation == true
        }

        has_key(obj, key) {
          _ = obj[key]
        }
```

**Constraint 적용**:
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sContainerNoPrivilegeEscalation
metadata:
  name: require-no-privilege-escalation-production
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces:
      - "kube-system"
      - "kube-public" 
      - "gatekeeper-system"
  enforcementAction: deny
```

### 2. 리소스 제한 강제 정책

**ConstraintTemplate**:
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8scontainerresourcelimits
  annotations:
    description: "모든 컨테이너에 리소스 제한을 강제합니다"
spec:
  crd:
    spec:
      names:
        kind: K8sContainerResourceLimits
      validation:
        openAPIV3Schema:
          type: object
          properties:
            exemptNamespaces:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8scontainerresourcelimits

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources
          msg := sprintf("컨테이너 '%v'에 리소스 설정이 없습니다", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.resources
          not container.resources.limits.cpu
          msg := sprintf("컨테이너 '%v'에 CPU 제한이 없습니다", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.resources
          not container.resources.limits.memory
          msg := sprintf("컨테이너 '%v'에 메모리 제한이 없습니다", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.resources
          not container.resources.requests.cpu
          msg := sprintf("컨테이너 '%v'에 CPU 요청이 없습니다", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.resources
          not container.resources.requests.memory
          msg := sprintf("컨테이너 '%v'에 메모리 요청이 없습니다", [container.name])
        }
```

---

## 🔧 실무 트러블슈팅

### 1. 일반적인 오류들

#### API 버전 오류
```bash
# ❌ 잘못된 버전
apiVersion: templates.gatekeeper.sh/v1

# ✅ 올바른 버전  
apiVersion: templates.gatekeeper.sh/v1beta1
```

#### nginx + runAsNonRoot 충돌
```yaml
# ❌ 문제 있는 설정
containers:
- name: nginx
  image: nginx:alpine  # root로 실행되는 이미지
  securityContext:
    runAsNonRoot: true  # 충돌!

# ✅ 올바른 설정
containers:
- name: nginx
  image: nginxinc/nginx-unprivileged:alpine
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    allowPrivilegeEscalation: false
```

### 2. 정책 업데이트 문제

**ConstraintTemplate 변경 시**:
```bash
# 1. 기존 Constraint 삭제
kubectl delete constraint-name

# 2. ConstraintTemplate 삭제  
kubectl delete constrainttemplate template-name

# 3. 잠시 대기
sleep 10

# 4. 새 템플릿 적용
kubectl apply -f new-template.yaml

# 5. 새 Constraint 적용
kubectl apply -f new-constraint.yaml
```

### 3. Rego 로직 디버깅

**안전한 필드 접근**:
```rego
# ❌ 위험한 방식
has_field(obj, field) {
  obj[field]  # false 값일 때 문제
}

# ✅ 안전한 방식
has_key(obj, key) {
  _ = obj[key]  # 존재 여부만 확인
}
```

---

## 📊 모니터링 및 감사

### 감사 스크립트
```bash
#!/bin/bash
# audit-report.sh

echo "=== Gatekeeper 정책 감사 리포트 ==="
echo "생성 시간: $(date)"
echo ""

echo "1. ConstraintTemplate 상태:"
kubectl get constrainttemplates -o custom-columns="NAME:.metadata.name,READY:.status.created"

echo ""
echo "2. 정책 위반 현황:"

# 권한 상승 금지 정책
echo "  권한 상승 금지:"
kubectl get k8scontainernoprivilegeescalation -o custom-columns="NAME:.metadata.name,VIOLATIONS:.status.totalViolations" 2>/dev/null || echo "    정책 없음"

# 리소스 제한 정책  
echo "  리소스 제한:"
kubectl get k8scontainerresourcelimits -o custom-columns="NAME:.metadata.name,VIOLATIONS:.status.totalViolations" 2>/dev/null || echo "    정책 없음"

echo ""
echo "3. Gatekeeper 시스템 상태:"
kubectl get pods -n gatekeeper-system --no-headers | awk '{print $1 ": " $3}'

echo ""
echo "4. 최근 위반 이벤트 (최근 1시간):"
kubectl get events --all-namespaces --field-selector reason=FailedCreate --sort-by='.lastTimestamp' | grep -E "($(date -d '1 hour ago' '+%Y-%m-%d')|$(date '+%Y-%m-%d'))" | tail -10

echo ""
echo "=== 감사 완료 ==="
```

### 위반 현황 모니터링
```bash
# 실시간 정책 위반 모니터링
kubectl get constraints --all-namespaces -o json | jq '.items[] | select(.status.totalViolations > 0) | {name: .metadata.name, violations: .status.totalViolations}'

# 특정 정책의 상세 위반 정보
kubectl get k8scontainerresourcelimits policy-name -o jsonpath='{.status.violations}' | jq .
```

---

## 🎯 운영 베스트 프랙티스

### 1. 점진적 배포 전략

```yaml
# 1단계: warn 모드로 시작
spec:
  enforcementAction: warn

# 2단계: dryrun으로 영향도 확인  
spec:
  enforcementAction: dryrun

# 3단계: 실제 적용
spec:
  enforcementAction: deny
```

### 2. 네임스페이스 전략

```yaml
# 프로덕션 권장 설정
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces:
      - "kube-system"
      - "kube-public"
      - "kube-node-lease"
      - "gatekeeper-system"
      - "cert-manager"
      - "ingress-nginx"
      - "monitoring"
      - "logging"
```

### 3. 정책 테스트 패턴

```yaml
# 실패해야 하는 테스트
apiVersion: v1
kind: Pod
metadata:
  name: test-should-fail
  namespace: test-namespace
spec:
  containers:
  - name: app
    image: nginx:alpine
    # 의도적으로 보안 설정 누락

---
# 성공해야 하는 테스트  
apiVersion: v1
kind: Pod
metadata:
  name: test-should-pass
  namespace: test-namespace
spec:
  containers:
  - name: app
    image: nginxinc/nginx-unprivileged:alpine
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"
```

### 4. 운영 체크리스트

**배포 전**:
- [ ] 정책을 warn 모드로 테스트
- [ ] 기존 워크로드 영향도 분석
- [ ] 예외 네임스페이스 설정 확인
- [ ] 롤백 계획 수립

**배포 후**:
- [ ] 정책 위반 현황 모니터링
- [ ] Gatekeeper 시스템 리소스 사용량 확인
- [ ] 애플리케이션 배포 영향도 확인
- [ ] 감사 리포트 정기 실행

**정기 점검**:
- [ ] 주간 정책 위반 리포트 검토
- [ ] 월간 정책 효과성 분석
- [ ] 분기별 정책 업데이트 검토

---

## ⚠️ 주의사항

1. **성능 영향**: Gatekeeper는 모든 리소스 생성 시 검증하므로 성능에 영향을 줄 수 있음
2. **시스템 네임스페이스**: 반드시 시스템 네임스페이스는 제외해야 함
3. **정책 순서**: 여러 정책이 있을 때 충돌 가능성 검토 필요
4. **업그레이드**: Gatekeeper 업그레이드 시 정책 호환성 확인 필요

---

이 가이드를 통해 Kubernetes 환경에서 OPA Gatekeeper를 안전하고 효과적으로 운영할 수 있습니다! 🚀
