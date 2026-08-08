# Trợ lý phân tích phishing dành cho SOC

[English](../README.md)

## Mục tiêu đồ án

Đây là đồ án portfolio an ninh mạng để phân tích email RFC 5322 đáng ngờ. Project hỗ trợ analyst đưa ra đánh giá rủi ro có thể giải thích được; không thay thế mail gateway, sandbox hay người xử lý sự cố.

Một pipeline dùng chung phục vụ CLI không cần credentials, Telegram Bot và FastAPI. Phạm vi được giữ vừa phải để dễ demo khi phỏng vấn: local-first, có giới hạn tài nguyên và có báo cáo rõ ràng.

## Demo trong năm phút

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OFFLINE_MODE='true'
$env:LOCAL_AI_ENABLED='false'
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-en.eml --offline
```

Bốn email trong [`samples/`](../samples) đều inert và chỉ dùng domain `.test` được dành riêng. Có thể demo tiếng Việt bằng lệnh sau:

```powershell
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-vi.eml --offline --output artifacts\demo-phishing-vi.md
```

## Ví dụ báo cáo

Báo cáo hiển thị tóm tắt mối đe dọa, bằng chứng SPF/DKIM/DMARC, IOC, giải thích điểm số và hành động tiếp theo:

```text
RISK ASSESSMENT
Score   : 100 / 100
Verdict : CRITICAL

RECOMMENDED SOC ACTIONS
• Quarantine the message and block confirmed malicious IOCs.
```

## Năng lực SOC được thể hiện

| Chức năng | Kỹ năng SOC thể hiện |
|---|---|
| Phân tích header và SPF/DKIM/DMARC | Xác thực và triage email |
| Trích xuất và tóm tắt IOC | Xử lý URL, domain, SHA-256 |
| URL, redirect, QR và attachment | Điều tra phishing/malware |
| VirusTotal, OTX, IP reputation, passive DNS | Threat-intelligence enrichment |
| Điểm rủi ro có thể giải thích | Ưu tiên và tương quan bằng chứng |
| AI local Anh–Việt | Inference ML local an toàn và provenance |
| API/Bot được harden | Validation, SSRF, rate limit, cleanup |
| Báo cáo SOC và action | Giao tiếp analyst và phản ứng sự cố |

## Pipeline hoạt động như thế nào

1. Parse `.eml`, header và body an toàn.
2. Phân tích xác thực, bất thường header, giả mạo display name và ngôn ngữ.
3. Trích xuất có giới hạn URL, QR URL, attachment và SHA-256.
4. Phân tích URL/domain/threat intel có giới hạn; `--offline` tắt enrichment qua mạng.
5. Kết hợp bằng chứng deterministic với AI tùy chọn để tạo score và report.

URL fetch chặn địa chỉ private/mixed DNS, pin public IP đã xác thực, xác thực lại redirect, giới hạn bytes/redirect/deadline và cô lập input lỗi.

## AI local Anh–Việt

Classifier local-first tùy chọn dùng artifact `jhu-clsp/mmBERT-small` đã promote. Model weights được chủ động không lưu trong Git. Nếu artifact hoặc ML dependency chưa có, report hiển thị trạng thái AI unavailable nhưng bằng chứng deterministic vẫn chạy.

Sau khi cài `requirements-ml.txt`, có thể tái tạo luồng train/promote:

```powershell
python -m ml.prepare_data --source public --raw-dir data/raw --output-dir data/processed/phishing --seed 42
python -m ml.train_mmbert --data-dir data/processed/phishing --output-dir artifacts/mmbert-candidate --epochs 1 --seed 42
python -m ml.promote promote --candidate artifacts/mmbert-candidate --target artifacts/models/phishing-mmbert --baseline-metrics artifacts/baseline-full/metrics.json
```

## Cài đặt

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Để chạy local inference tùy chọn, cài Torch wheel phù hợp với máy trước, sau đó:

```powershell
pip install -r requirements-ml-runtime.txt
```

Chỉ cần copy `.env.example` sang `.env` khi dùng external service, bot, API authentication hoặc artifact model local. Demo CLI offline không cần token/API key.

## Telegram Bot

Đặt `TELEGRAM_TOKEN` trong `.env`, sau đó chạy:

```powershell
python main.py
```

Bot nhận `.eml`, kiểm tra metadata và kích thước file đã tải thực tế, offload phân tích khỏi event loop và xóa file tạm sau khi xử lý.

## REST API

Khởi động API với `API_KEY` (hoặc `ENV=dev` khi test local):

```powershell
python main.py --api
```

`POST /analyze_email` và `POST /analyze_file` trả report, risk evidence, AI provider/model provenance, `analysis_limits`, request ID và header `X-Request-ID`.

## Docker

Core image loại trừ secret, artifact, dataset, upload, cache và worktree khỏi build context; image này không tải PyTorch:

```powershell
docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .
docker run --rm --env TELEGRAM_ENABLED=false phishing-triage-bot:core python main.py --healthcheck
```

Build image local-AI CPU tùy chọn và mount weights read-only:

```powershell
docker build --build-arg INSTALL_LOCAL_AI=true -t phishing-triage-bot:ai .
docker run --rm --env-file .env -v "${PWD}/artifacts/models/phishing-mmbert:/app/artifacts/models/phishing-mmbert:ro" phishing-triage-bot:ai
```

## Kiểm thử và kiểm soát bảo mật

```powershell
python -m pytest -q tests -W error
python -m ruff check .
python -m black --check api bot cli.py config email_analysis ml report scoring threat_intel main.py tests
python -m mypy api bot cli.py config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
python -m bandit -r api bot config email_analysis ml report scoring threat_intel -lll
python -m pip_audit
```

GitHub Actions kiểm tra Python 3.12/3.13, smoke CLI offline và core Docker build.

## Kết quả model và giới hạn

Kết quả evaluation đã promote: English macro-F1 **0.9812**, phishing recall **0.9761**, FPR **0.0141**. Evaluation bằng **dữ liệu tiếng Việt tổng hợp** đạt macro-F1 **0.8789**, recall **0.94**, FPR **0.1818**.

Kết quả tiếng Việt tổng hợp chỉ phù hợp để regression evaluation, không chứng minh độ chính xác production. Output model là một nguồn bằng chứng cùng với các signal deterministic, nên vẫn cần analyst xác thực.

## Sử dụng có trách nhiệm

Project phục vụ triage phòng thủ, học tập và test có kiểm soát. Không dùng để detonating malware, tự động xử phạt người dùng hay đưa ra quyết định ảnh hưởng cao nếu chưa điều tra và review con người. Xem [SECURITY.md](../SECURITY.md) để biết cách xử lý sample và secret.

## Giấy phép

MIT. Xem [LICENSE](../LICENSE).
