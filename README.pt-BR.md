[🇺🇸 English](README.md) | **🇧🇷 Português**

# 🛡️ pii-screenshot-guard

CLI e biblioteca Python de **Prevenção contra Vazamento de Dados (Zero-Trust DLP)** para detectar **dados pessoais (LGPD/GDPR)**, **chaves de API/tokens**, **strings de conexão com senha** e **IPs internos (RFC 1918)** em logs, chamados, diffs e capturas de tela antes do compartilhamento.

---

## Principais Recursos

- **Zero dependências obrigatórias no núcleo:** roda apenas com a biblioteca padrão do Python 3.10+.
- **Validação matemática anti-falso-positivo:** valida **CPF** e **CNPJ** (módulo 11) e **cartões de pagamento** (algoritmo de Luhn).
- **Relatórios seguros:** nunca exibe o segredo completo no terminal (aplica mascaramento automático como `AKI***LE`).
- **Pronto para CI/CD:** suporte a `--fail-on`, saída em `table`, `markdown` e `json`, leitura via `stdin` (`-`) e sanitização automática (`redact`).
- **Suporte opcional para imagens/prints:** conectores `TesseractOCRAnalyzer` (offline) e `GeminiVisionAnalyzer` (multimodal via `GEMINI_API_KEY`).

---

## Uso Rápido

```bash
pip install .

# Escanear pasta e retornar erro se houver achado MEDIUM ou superior
pii-guard scan ./logs --fail-on medium --format markdown

# Redigir (mascarar) arquivo sensível
pii-guard redact app.log -o app.sanitized.log
```

## Testes

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Consulte a documentação completa em [README.md](README.md) e os termos da licença em [LICENSE](LICENSE).
