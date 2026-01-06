# 🛡️ Kernel Attack Detect (eBPF & ML 기반 커널 공격 탐지)

이 프로젝트는 **eBPF(BCC)**를 활용하여 리눅스 커널 레벨의 데이터를 실시간으로 수집하고, **Machine Learning(XGBoost, AdaBoost)** 모델을 통해 커널 공격(비정상 시스템 콜 호출 및 힙 스프레이)을 탐지하는 보안 솔루션입니다.

---

## 🚀 주요 기능

- **Syscall 모니터링 및 탐지**: 시스템 콜 호출 빈도, 인자 유사도, 상위 호출 시스템 콜 패턴을 분석하여 프로세스의 비정상 행위를 탐지합니다.
- **Heap Spray 탐지**: `kmalloc` 및 `kfree` 이벤트를 추적하여 메모리 할당 패턴의 엔트로피(Entropy)와 지니 계수(Gini Index)를 계산, 힙 스프레이 공격을 실시간으로 감지합니다.
- **Low Overhead**: 커널 레벨에서 eBPF를 사용하여 모니터링 부하를 최소화하였습니다.

---

## 🏗️ 시스템 아키텍처

1. **Kernel Space (eBPF)**: Tracepoint(`raw_syscalls`, `kmem`)를 통해 이벤트를 캡처하고 BPF Map에 데이터를 저장합니다.
2. **User Space (BCC/Python)**: BPF Map의 데이터를 배치 단위로 읽어와 통계적 피처를 추출합니다.
3. **ML Inference**: 학습된 모델(`XGBoost`, `AdaBoost`)에 데이터를 입력하여 실시간 위험도를 출력합니다.

---

## 📂 스크립트 구성

### 1. 시스템 콜(Syscall) 분석 모듈
| 파일명 | 역할 | 상세 설명 |
| :--- | :--- | :--- |
| `syscall_collector.py` | 데이터 수집 | eBPF를 통해 시스템 콜 로그를 수집하고 CSV로 저장합니다. |
| `syscall_trainer.py` | 모델 학습 | 수집된 CSV를 기반으로 XGBoost/AdaBoost 모델을 학습합니다. |
| `syscall_detector.py` | 실시간 탐지 | 학습된 모델을 로드하여 현재 시스템의 위험 프로세스를 실시간 탐지합니다. |

### 2. 커널 메모리(Kmalloc) 분석 모듈
| 파일명 | 역할 | 상세 설명 |
| :--- | :--- | :--- |
| `kmalloc_collector.py` | 데이터 수집 | `kmalloc` 할당 패턴(엔트로피, 지니계수)을 수집하여 저장합니다. |
| `kmalloc_trainer.py` | 모델 학습 | 메모리 할당 불균형 지표를 기반으로 AdaBoost 모델을 학습합니다. |
| `kmalloc_detector.py` | 실시간 탐지 | 실시간으로 계산된 지표를 모델에 입력하여 힙 공격 여부를 판별합니다. |

---

## 📊 핵심 피처 (Features)

### 시스템 콜 분석
- `SYSCALL_TOTAL_COUNT`: 전체 시스템 콜 호출 횟수
- `SYSCALL_ARGUMENT_SIMILAR`: 호출 인자의 유사도 (반복적 인자 주입 탐지)
- `SYSCALL_TOP1~6`: 빈도가 가장 높은 시스템 콜들의 호출 횟수

### 메모리 할당 분석
- **엔트로피(Entropy)**: 메모리 할당 크기 분포의 무질서도 측정
- **지니 계수(Gini Index)**: 특정 슬랩(Slab)에 할당이 집중되는 불균형 정도 측정 (힙 스프레이의 핵심 지표)

---

## 🛠️ 설치 및 실행 방법

### 요구 사항
- Linux Kernel 5.x 이상 (Tracepoint 지원)
- Python 3.8+
- BCC (BPF Compiler Collection)
- Dependencies: `pandas`, `scikit-learn`, `xgboost`, `joblib`, `dill`

### 실행 순서

1. **데이터 수집**
   ```bash
   sudo python3 syscall_collector.py -n [대상프로세스명] -l [레이블]
