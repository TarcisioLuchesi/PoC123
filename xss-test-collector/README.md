# Coletor de eventos sintéticos para testes XSS

Este coletor local aceita **somente marcadores fictícios**, para validar execução de JavaScript em ambientes próprios ou autorizados. **Não aceita cookies, tokens, credenciais ou conteúdo arbitrário.**

## Executar

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Servidor local: http://127.0.0.1:5000/health

## Testar

```bash
curl -X POST http://127.0.0.1:5000/event -H "Content-Type: application/json" -d '{"test_id":"lab-001","marker":"XSS_TEST_OK"}'
```

Ou, de uma página no mesmo origin ou via proxy controlado:

```javascript
fetch('/event', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({test_id:'lab-001',marker:'XSS_TEST_OK'})});
```

Requisições de outra origem exigem configuração explícita de CORS ou um proxy no ambiente autorizado. O servidor não define CORS aberto.

## Implantação

GitHub Pages **não executa Python** nem recebe POSTs dinamicamente. Este diretório é código-fonte: execute o backend em sua máquina, VPS ou serviço de hospedagem Python. Antes de expor à internet, configure HTTPS, autenticação, limitação de requisições e monitoração. Não armazene dados sensíveis. 
